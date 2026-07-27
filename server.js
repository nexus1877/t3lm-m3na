const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  const { data: existing, error: checkErr } = await supabase
    .from('users')
    .select('email')
    .eq('email', email)
    .maybeSingle();
  if (checkErr) return res.status(500).json({ error: checkErr.message });
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('users')
    .insert([{ username, email, password_hash: hashed }])
    .select('id, username, email');
  if (error) return res.status(500).json({ error: error.message });
  const token = jwt.sign({ userId: data[0].id, email: data[0].email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: data[0], token });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const { data, error } = await supabase
    .from('users')
    .select('id, username, email, password_hash')
    .eq('email', email)
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: data.id, email: data.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ user: { id: data.id, username: data.username, email: data.email }, token });
});

app.post('/api/verify', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data, error } = await supabase
      .from('users')
      .select('id, username, email')
      .eq('id', decoded.userId)
      .maybeSingle();
    if (error || !data) return res.status(401).json({ error: 'Invalid token' });
    res.json({ user: data });
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server running on port ' + (process.env.PORT || 3000)));
