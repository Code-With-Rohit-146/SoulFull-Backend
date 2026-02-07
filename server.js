import express from 'express';
import cors from 'cors';
import { Client } from "@gradio/client";
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const sessions = new Map();

const app = express();
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173'];
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

let client;
let isConnecting = false;

async function connectToGradio() {
  if (isConnecting) return;
  isConnecting = true;
  try {
    console.log("Connecting to Gradio Space (30s timeout)...");
    client = await Client.connect("rohitMukhi/my-groq-app", {
      timeout: 30000 
    });
    console.log("Successfully connected to rohitMukhi/my-groq-app");
  } catch (error) {
    console.error("Failed to connect to Gradio Space:", error.message);
    client = null;
  } finally {
    isConnecting = false;
  }
}

connectToGradio();

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, username, fullName } = req.body;
    
    if (!email || !password || !username || !fullName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 8 || !/[A-Z]/.test(password) || !/\d/.test(password)) {
      return res.status(400).json({ error: 'Password must be 8+ characters with uppercase and digit' });
    }

    const { data: existingUsers, error: checkError } = await supabase
      .from('Users')
      .select('id')
      .or(`Email.eq.${email},Username.eq.${username}`);

    if (checkError) {
      console.error('Check error:', checkError);
      return res.status(500).json({ error: 'Database error: ' + checkError.message });
    }

    if (existingUsers && existingUsers.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const { data: newUser, error: insertError } = await supabase
      .from('Users')
      .insert([{ 
        Name: fullName, 
        Email: email, 
        Username: username, 
        Password: hashedPassword 
      }])
      .select()
      .single();

    if (insertError) {
      console.error('Insert error:', insertError);
      return res.status(500).json({ error: 'Failed to create user: ' + insertError.message });
    }

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { userId: newUser.id, email, username, fullName });

    res.json({ 
      user: { id: newUser.id, email, user_metadata: { username, full_name: fullName } },
      session: { access_token: token }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const { data: user, error } = await supabase
      .from('Users')
      .select('*')
      .eq('Username', username)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User does not exist' });
    }

    const validPassword = await bcrypt.compare(password, user.Password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { userId: user.id, email: user.Email, username: user.Username, fullName: user.Name });

    res.json({ 
      user: { id: user.id, email: user.Email, user_metadata: { username: user.Username, full_name: user.Name } },
      session: { access_token: token }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/logout', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) sessions.delete(token);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const verifySession = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  
  req.user = { id: session.userId };
  next();
};

app.post('/api/chat', verifySession, async (req, res) => {
  try {
    if (!req.body || !req.body.messages || !Array.isArray(req.body.messages)) {
      return res.status(400).json({ error: "Invalid request format" });
    }

    const { messages } = req.body;
    const lastMessage = messages[messages.length - 1];
    const lastUserMessage = lastMessage.content || lastMessage.text;

    if (!lastUserMessage) {
      return res.status(400).json({ error: "No message content found" });
    }

    if (!client && !isConnecting) {
      await connectToGradio();
    }
    
    if (!client) {
      return res.json({ 
        role: "assistant", 
        content: "I'm here to listen and support you. The AI service is temporarily unavailable, but please know that your feelings are valid and you're not alone." 
      });
    }

    const result = await client.predict("/chat", { 
      msg: lastUserMessage 
    });

    res.json({ 
      role: "assistant", 
      content: result.data[0] 
    });

  } catch (error) {
    console.error("Error communicating with Gradio:", error);
    res.json({ 
      role: "assistant", 
      content: "Thank you for sharing. I'm here to support you, even though I'm having some technical difficulties right now." 
    });
  }
});

app.post('/api/report', verifySession, async (req, res) => {
  try {
    const { chatHistory } = req.body;
    
    if (!chatHistory || chatHistory.length === 0) {
      return res.status(400).json({ error: "No chat history provided" });
    }

    const userMessages = chatHistory.filter(msg => msg.sender === 'user').map(msg => msg.text).join('. ');
    const analysisPrompt = `Based on this conversation: "${userMessages}", provide a 30-word emotional state analysis.`;
    const metricsPrompt = `Based on this conversation: "${userMessages}", rate the following on a scale of 1-10: Stress Level, Depression Severity, Anxiety Level. Respond in format: Stress: X, Depression: X, Anxiety: X`;
    const suggestionsPrompt = `Based on this conversation: "${userMessages}", provide 3-5 practical suggestions to improve their mental wellbeing.`;

    if (!client && !isConnecting) {
      await connectToGradio();
    }
    
    if (!client) {
      return res.json({ 
        report: "Unable to generate report at this time. The AI service is temporarily unavailable.",
        metrics: { stress: 0, depression: 0, anxiety: 0 },
        suggestions: "Unable to generate suggestions at this time."
      });
    }

    const analysisResult = await client.predict("/chat", { msg: analysisPrompt });
    const metricsResult = await client.predict("/chat", { msg: metricsPrompt });
    const suggestionsResult = await client.predict("/chat", { msg: suggestionsPrompt });
    
    const metricsText = metricsResult.data[0];
    const stressMatch = metricsText.match(/Stress:?\s*(\d+)/i);
    const depressionMatch = metricsText.match(/Depression:?\s*(\d+)/i);
    const anxietyMatch = metricsText.match(/Anxiety:?\s*(\d+)/i);

    res.json({ 
      report: analysisResult.data[0],
      metrics: {
        stress: stressMatch ? parseInt(stressMatch[1]) : 5,
        depression: depressionMatch ? parseInt(depressionMatch[1]) : 5,
        anxiety: anxietyMatch ? parseInt(anxietyMatch[1]) : 5
      },
      suggestions: suggestionsResult.data[0]
    });

  } catch (error) {
    console.error("Error generating report:", error);
    res.json({ 
      report: "Unable to generate report due to technical difficulties. Please try again later.",
      metrics: { stress: 0, depression: 0, anxiety: 0 },
      suggestions: "Unable to generate suggestions at this time."
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));