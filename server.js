const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));

const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = String(process.env.DEMO_MODE || 'true').toLowerCase() === 'true';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const UPIQRPAY_BASE_URL = String(process.env.UPIQRPAY_BASE_URL || 'https://upiqrpay.in/api/v1').replace(/\/$/, '');
const UPIQRPAY_API_KEY = process.env.UPIQRPAY_API_KEY || '';
const UPIQRPAY_WEBHOOK_SECRET = process.env.UPIQRPAY_WEBHOOK_SECRET || '';
const PUBLIC_BASE_URL = String(process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');

const defaultProducts = [
  { id: 1, name: 'FIRE X LOADER', plans: [
    { id: 1, duration: '5 Hours Access', price: 30 }, { id: 2, duration: '1 Day Access', price: 100 },
    { id: 3, duration: '3 Days Access', price: 250 }, { id: 4, duration: '7 Days Access', price: 400 },
    { id: 5, duration: '30 Days Access', price: 800 }, { id: 6, duration: '60 Days Access', price: 1200 }
  ]},
  { id: 2, name: 'MARS LOADER', plans: [
    { id: 7, duration: '5 Hours Access', price: 40 }, { id: 8, duration: '1 Day Access', price: 120 },
    { id: 9, duration: '3 Days Access', price: 300 }, { id: 10, duration: '7 Days Access', price: 450 },
    { id: 11, duration: '30 Days Access', price: 900 }, { id: 12, duration: '60 Days Access', price: 1400 }
  ]}
];

const memory = { products: defaultProducts, orders: [], licenses: [], nextOrder: 100001 };
const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false })
  : null;

async function dbQuery(text, params) { return pool.query(text, params); }

async function initDb() {
  if (!pool) return;
  await dbQuery(`CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE);`);
  await dbQuery(`CREATE TABLE IF NOT EXISTS plans (id SERIAL PRIMARY KEY, product_id INTEGER REFERENCES products(id) ON DELETE CASCADE, duration TEXT NOT NULL, price NUMERIC(10,2) NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE);`);
  await dbQuery(`CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, product_id INTEGER NOT NULL, plan_id INTEGER NOT NULL, amount NUMERIC(10,2) NOT NULL, status TEXT NOT NULL, payment_reference TEXT, license_key TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_provider TEXT;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id TEXT;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_name TEXT;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_phone TEXT;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS licence_status TEXT NOT NULL DEFAULT 'PENDING';`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS licence_issued_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);
  await dbQuery(`CREATE UNIQUE INDEX IF NOT EXISTS orders_payment_id_unique ON orders(payment_id) WHERE payment_id IS NOT NULL;`);
  await dbQuery(`CREATE TABLE IF NOT EXISTS admin_users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, secret_hash TEXT NOT NULL);`);
  const count = await dbQuery('SELECT COUNT(*)::int AS n FROM products');
  if (count.rows[0].n === 0) {
    for (const p of defaultProducts) {
      const r = await dbQuery('INSERT INTO products(name) VALUES($1) RETURNING id', [p.name]);
      for (const plan of p.plans) await dbQuery('INSERT INTO plans(product_id,duration,price) VALUES($1,$2,$3)', [r.rows[0].id, plan.duration, plan.price]);
    }
  }
  const email = process.env.ADMIN_EMAIL || 'admin@example.com';
  const password = process.env.ADMIN_PASSWORD || 'admin123';
  const secret = process.env.ADMIN_SECRET || '123456';
  const exists = await dbQuery('SELECT id FROM admin_users WHERE email=$1', [email]);
  if (!exists.rowCount) await dbQuery('INSERT INTO admin_users(email,password_hash,secret_hash) VALUES($1,$2,$3)', [email, await bcrypt.hash(password, 12), await bcrypt.hash(secret, 12)]);
}

function makeKey() {
  const part = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `MS-${part()}-${part()}-${part()}-${part()}`;
}

function signAdmin(email) { return jwt.sign({ sub: email, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try { const payload = jwt.verify(token, JWT_SECRET); if (payload.role !== 'admin') throw new Error(); req.admin = payload; next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

async function getProducts() {
  if (!pool) return memory.products;
  const r = await dbQuery(`SELECT p.id AS product_id,p.name,pl.id AS plan_id,pl.duration,pl.price FROM products p JOIN plans pl ON pl.product_id=p.id WHERE p.active=true AND pl.active=true ORDER BY p.id,pl.id`);
  const map = new Map();
  for (const x of r.rows) {
    if (!map.has(x.product_id)) map.set(x.product_id, { id:x.product_id, name:x.name, plans:[] });
    map.get(x.product_id).plans.push({ id:x.plan_id, duration:x.duration, price:Number(x.price) });
  }
  return [...map.values()];
}

async function findSelection(productId, planId) {
  const products = await getProducts();
  const product = products.find(p => p.id === Number(productId));
  const plan = product?.plans.find(x => x.id === Number(planId));
  if (!product || !plan) throw new Error('Invalid product or plan');
  return { product, plan };
}

function requirePaymentConfig() {
  if (!UPIQRPAY_API_KEY) throw new Error('UPIQRPay API key is not configured');
  if (!PUBLIC_BASE_URL) throw new Error('PUBLIC_BASE_URL is not configured');
  if (!/^https:\/\//i.test(PUBLIC_BASE_URL)) throw new Error('PUBLIC_BASE_URL must use HTTPS');
}

async function upiqrpayRequest(endpoint, body) {
  requirePaymentConfig();
  const r = await fetch(`${UPIQRPAY_BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPIQRPAY_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.success === false) {
    const message = data?.error || data?.message || `UPIQRPay returned HTTP ${r.status}`;
    throw new Error(message);
  }
  return data;
}

async function upiqrpayStatus(paymentId) {
  requirePaymentConfig();
  const r = await fetch(`${UPIQRPAY_BASE_URL}/order/status/${encodeURIComponent(paymentId)}`, {
    headers: { Authorization: `Bearer ${UPIQRPAY_API_KEY}` }
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok || data.success === false) {
    const message = data?.error || data?.message || `UPIQRPay returned HTTP ${r.status}`;
    throw new Error(message);
  }
  return data?.data || data;
}

// IMPORTANT: this route is registered before express.json() so HMAC is calculated
// over the exact raw request body sent by UPIQRPay.
app.post('/api/webhooks/upiqrpay', express.raw({ type: ['application/json', 'application/*+json'], limit: '100kb' }), async (req, res) => {
  try {
    if (!UPIQRPAY_WEBHOOK_SECRET) return res.status(503).json({ error: 'Webhook secret is not configured' });
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    const received = String(req.headers['x-upiqrpay-signature'] || '').trim().toLowerCase();
    if (!received) return res.status(401).json({ error: 'Missing webhook signature' });
    const expected = crypto.createHmac('sha256', UPIQRPAY_WEBHOOK_SECRET).update(rawBody).digest('hex').toLowerCase();
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(received, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Invalid webhook signature' });

    const event = JSON.parse(rawBody.toString('utf8'));
    const paymentId = String(event.payment_id || '').trim();
    const orderId = String(event.order_id || '').trim();
    const status = String(event.status || '').toLowerCase();
    const amount = Number(event.amount);
    if (!paymentId || !orderId || !status || !Number.isFinite(amount)) return res.status(400).json({ error: 'Invalid webhook payload' });

    if (pool) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const r = await client.query('SELECT * FROM orders WHERE id=$1 FOR UPDATE', [orderId]);
        if (!r.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Order not found' }); }
        const order = r.rows[0];
        if (Number(order.amount) !== amount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Payment amount mismatch' }); }

        if (order.status === 'PAID') {
          await client.query('COMMIT');
          return res.status(200).json({ ok: true, duplicate: true });
        }

        if (status === 'success') {
          await client.query(`UPDATE orders SET status='PAID', payment_provider='upiqrpay', payment_id=$1, payment_status='success', payment_reference=$1, paid_at=NOW(), updated_at=NOW(), licence_status='PENDING' WHERE id=$2`, [paymentId, orderId]);
        } else if (['expired','cancelled'].includes(status)) {
          await client.query(`UPDATE orders SET payment_provider='upiqrpay', payment_id=$1, payment_status=$2, status='EXPIRED', updated_at=NOW() WHERE id=$3`, [paymentId, status, orderId]);
        } else {
          await client.query(`UPDATE orders SET payment_provider='upiqrpay', payment_id=$1, payment_status=$2, updated_at=NOW() WHERE id=$3`, [paymentId, status, orderId]);
        }
        await client.query('COMMIT');
        return res.status(200).json({ ok: true });
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally { client.release(); }
    }

    const order = memory.orders.find(x => x.id === orderId);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (Number(order.amount) !== amount) return res.status(400).json({ error: 'Payment amount mismatch' });
    if (order.status === 'PAID') return res.status(200).json({ ok: true, duplicate: true });
    order.paymentId = paymentId;
    order.paymentStatus = status;
    order.paymentReference = paymentId;
    order.updatedAt = new Date().toISOString();
    if (status === 'success') { order.status = 'PAID'; order.paidAt = new Date().toISOString(); order.licenceStatus = 'PENDING'; }
    else if (['expired','cancelled'].includes(status)) order.status = 'EXPIRED';
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('UPIQRPay webhook error:', e.message);
    return res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.use(express.json({ limit: '100kb' }));
app.use(morgan('tiny'));

app.get('/api/health', (req,res)=>res.json({ ok:true, database:!!pool, demoMode:DEMO_MODE, paymentProvider:UPIQRPAY_API_KEY ? 'upiqrpay' : null }));
app.get('/api/products', async (req,res)=>{ try { res.json({ products: await getProducts() }); } catch(e){ res.status(500).json({error:e.message}); } });

app.post('/api/orders', async (req,res)=>{
  try {
    const { productId, planId } = req.body;
    const { product, plan } = await findSelection(productId, planId);
    const id = `ORD-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    if (pool) await dbQuery('INSERT INTO orders(id,product_id,plan_id,amount,status,payment_status,licence_status) VALUES($1,$2,$3,$4,$5,$6,$7)', [id, product.id, plan.id, plan.price, 'PENDING', 'pending', 'PENDING']);
    else memory.orders.push({ id, productId:product.id, planId:plan.id, amount:plan.price, status:'PENDING', paymentStatus:'pending', licenceStatus:'PENDING', createdAt:new Date().toISOString(), updatedAt:new Date().toISOString() });
    res.status(201).json({ order:{ id, product, plan, amount:plan.price, status:'PENDING', licenceStatus:'PENDING' } });
  } catch(e) { res.status(400).json({ error:e.message }); }
});

app.post('/api/orders/:id/payment', async (req,res)=>{
  try {
    const id = req.params.id;
    const customerName = String(req.body?.customerName || '').trim();
    const customerPhone = String(req.body?.customerPhone || '').replace(/\s+/g, '');
    if (customerName.length < 2) return res.status(400).json({ error:'Customer name is required' });
    if (!/^\+?[0-9]{10,15}$/.test(customerPhone)) return res.status(400).json({ error:'Enter a valid customer phone number' });
    requirePaymentConfig();

    let order;
    if (pool) {
      const r = await dbQuery('SELECT o.*,p.name AS product_name,pl.duration,pl.price FROM orders o JOIN products p ON p.id=o.product_id JOIN plans pl ON pl.id=o.plan_id WHERE o.id=$1', [id]);
      if (!r.rowCount) return res.status(404).json({error:'Order not found'});
      order = r.rows[0];
      if (order.status === 'PAID') return res.status(409).json({error:'Order is already paid'});
      if (order.payment_id) return res.status(409).json({error:'Payment has already been created for this order'});
    } else {
      order = memory.orders.find(x=>x.id===id);
      if (!order) return res.status(404).json({error:'Order not found'});
      if (order.status === 'PAID') return res.status(409).json({error:'Order is already paid'});
      if (order.paymentId) return res.status(409).json({error:'Payment has already been created for this order'});
      const { product, plan } = await findSelection(order.productId, order.planId);
      order.product_name = product.name; order.duration = plan.duration;
    }

    const payload = {
      amount: Number(order.amount),
      order_id: id,
      customer_name: customerName,
      customer_phone: customerPhone,
      redirect_url: `${PUBLIC_BASE_URL}/?payment_return=1&order_id=${encodeURIComponent(id)}`,
      webhook_url: `${PUBLIC_BASE_URL}/api/webhooks/upiqrpay`
    };
    const provider = await upiqrpayRequest('/order/create', payload);
    const payment = provider.data || provider;
    const paymentId = String(payment.payment_id || '').trim();
    if (!paymentId) throw new Error('UPIQRPay response did not include payment_id');

    if (pool) {
      await dbQuery(`UPDATE orders SET payment_provider='upiqrpay', payment_id=$1, payment_status=$2, customer_name=$3, customer_phone=$4, updated_at=NOW() WHERE id=$5`, [paymentId, String(payment.status || 'pending').toLowerCase(), customerName, customerPhone, id]);
    } else {
      order.paymentId = paymentId; order.paymentStatus = String(payment.status || 'pending').toLowerCase(); order.customerName = customerName; order.customerPhone = customerPhone; order.paymentProvider='upiqrpay'; order.updatedAt=new Date().toISOString();
    }

    res.json({ payment: {
      paymentId,
      orderId: id,
      amount: Number(payment.amount ?? order.amount),
      status: payment.status || 'pending',
      qrCode: payment.qr_code || null,
      upiLink: payment.upi_link || null,
      payUrl: payment.pay_url || null,
      expiresAt: payment.expires_at || null
    }});
  } catch(e) {
    console.error('UPIQRPay create-order error:', e.message);
    res.status(502).json({ error:e.message });
  }
});

app.get('/api/orders/:id/status', async (req,res)=>{
  try {
    const id = req.params.id;
    let order;
    if (pool) {
      const r = await dbQuery('SELECT * FROM orders WHERE id=$1', [id]);
      if (!r.rowCount) return res.status(404).json({error:'Order not found'});
      order = r.rows[0];
    } else {
      order = memory.orders.find(x=>x.id===id);
      if (!order) return res.status(404).json({error:'Order not found'});
    }

    // Webhook is primary. For a pending order, status API is a controlled fallback.
    if (order.status !== 'PAID' && order.payment_id && UPIQRPAY_API_KEY) {
      try {
        const provider = await upiqrpayStatus(order.payment_id);
        const s = String(provider.status || '').toLowerCase();
        const amount = Number(provider.amount ?? order.amount);
        if (amount === Number(order.amount) && s === 'success') {
          if (pool) await dbQuery(`UPDATE orders SET status='PAID', payment_status='success', payment_reference=payment_id, paid_at=COALESCE(paid_at,NOW()), licence_status='PENDING', updated_at=NOW() WHERE id=$1`, [id]);
          else { order.status='PAID'; order.paymentStatus='success'; order.paidAt=order.paidAt||new Date().toISOString(); order.licenceStatus='PENDING'; order.updatedAt=new Date().toISOString(); }
          order.status='PAID';
        } else if (['expired','cancelled'].includes(s)) {
          if (pool) await dbQuery(`UPDATE orders SET status='EXPIRED', payment_status=$1, updated_at=NOW() WHERE id=$2`, [s,id]);
          else { order.status='EXPIRED'; order.paymentStatus=s; order.updatedAt=new Date().toISOString(); }
        }
      } catch (e) {
        // Don't turn a normal status poll into a hard failure; webhook may still arrive.
        console.warn('UPIQRPay status fallback:', e.message);
      }
    }

    if (pool) {
      const r = await dbQuery('SELECT id,status,payment_id,payment_status,amount,licence_status,license_key,paid_at,updated_at FROM orders WHERE id=$1',[id]);
      return res.json({order:r.rows[0]});
    }
    return res.json({order:{id:order.id,status:order.status,payment_id:order.paymentId||null,payment_status:order.paymentStatus||null,amount:order.amount,licence_status:order.licenceStatus||'PENDING',license_key:order.licenseKey||null,paid_at:order.paidAt||null,updated_at:order.updatedAt||null}});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Demo-only payment endpoint remains available only when DEMO_MODE=true.
app.post('/api/orders/:id/demo-pay', async (req,res)=>{
  if (!DEMO_MODE) return res.status(403).json({error:'Demo payment is disabled'});
  try {
    const id=req.params.id;
    if (pool) {
      const r=await dbQuery('SELECT * FROM orders WHERE id=$1',[id]);
      if(!r.rowCount) return res.status(404).json({error:'Order not found'});
      if(r.rows[0].status==='PAID') return res.json({order:r.rows[0]});
      const key=makeKey();
      await dbQuery('UPDATE orders SET status=$1,payment_reference=$2,license_key=$3,payment_status=$4,licence_status=$5,paid_at=NOW(),updated_at=NOW() WHERE id=$6',['PAID',`DEMO-${crypto.randomBytes(5).toString('hex')}`,key,'success','ISSUED',id]);
      return res.json({order:{id,status:'PAID',licenseKey:key}});
    }
    const order=memory.orders.find(x=>x.id===id); if(!order) return res.status(404).json({error:'Order not found'});
    if(order.status==='PAID') return res.json({order});
    order.status='PAID'; order.paymentReference=`DEMO-${crypto.randomBytes(5).toString('hex')}`; order.licenseKey=makeKey(); order.paymentStatus='success'; order.licenceStatus='ISSUED'; order.paidAt=new Date().toISOString(); order.updatedAt=new Date().toISOString();
    memory.licenses.push({ key:order.licenseKey, orderId:id, status:'ACTIVE', createdAt:new Date().toISOString() });
    res.json({order:{...order,licenseKey:order.licenseKey}});
  } catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/login', async (req,res)=>{
  const {email,password,secret}=req.body||{};
  if(!email||!password||!secret) return res.status(400).json({error:'Email, password and secret code are required'});
  try {
    let ok=false;
    if(pool){ const r=await dbQuery('SELECT * FROM admin_users WHERE email=$1',[email]); ok=!!r.rowCount && await bcrypt.compare(password,r.rows[0].password_hash) && await bcrypt.compare(secret,r.rows[0].secret_hash); }
    else { ok=email===(process.env.ADMIN_EMAIL||'admin@example.com') && password===(process.env.ADMIN_PASSWORD||'admin123') && secret===(process.env.ADMIN_SECRET||'123456'); }
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    res.json({token:signAdmin(email)});
  } catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/admin/stats', auth, async (req,res)=>{
  try {
    if(pool){ const [o,l]=await Promise.all([dbQuery("SELECT COUNT(*)::int AS n,COALESCE(SUM(amount) FILTER (WHERE status='PAID'),0) AS revenue FROM orders"),dbQuery("SELECT COUNT(*)::int AS n FROM orders WHERE status='PAID'")]); return res.json({orders:o.rows[0].n,revenue:Number(o.rows[0].revenue),paidOrders:l.rows[0].n}); }
    const paid=memory.orders.filter(x=>x.status==='PAID'); res.json({orders:memory.orders.length,revenue:paid.reduce((s,x)=>s+x.amount,0),paidOrders:paid.length});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/admin/orders', auth, async (req,res)=>{
  try { if(pool){const r=await dbQuery('SELECT * FROM orders ORDER BY created_at DESC LIMIT 100'); return res.json({orders:r.rows});} res.json({orders:[...memory.orders].reverse().slice(0,100)}); }
  catch(e){res.status(500).json({error:e.message});}
});

// Future real license provider integration point. Keep this separate from payment confirmation.
async function issueLicense({product, plan, orderId}) {
  // TODO: replace with your legitimate license-server API call when its documentation is provided.
  return { key: makeKey(), provider: 'local-demo', orderId, product: product.name, duration: plan.duration };
}

app.get('/api/admin/products', auth, async (req,res)=>{ try {res.json({products:await getProducts()});}catch(e){res.status(500).json({error:e.message});} });

app.use(express.static(path.join(__dirname,'public')));
app.use((req,res,next)=>{ if (req.method !== 'GET') return next(); res.sendFile(path.join(__dirname,'public','index.html')); });

initDb().then(()=>app.listen(PORT,()=>console.log(`Multi Server running on http://localhost:${PORT}`))).catch(err=>{console.error(err);process.exit(1)});
