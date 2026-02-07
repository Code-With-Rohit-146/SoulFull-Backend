-- Run this in Supabase SQL Editor to create the chat_history table

CREATE TABLE IF NOT EXISTS chat_history (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  user_message TEXT NOT NULL,
  bot_response TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE chat_history ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own chat history
CREATE POLICY "Users can view own chat history" 
  ON chat_history FOR SELECT 
  USING (auth.uid() = user_id);

-- Policy: Users can insert their own chat history
CREATE POLICY "Users can insert own chat history" 
  ON chat_history FOR INSERT 
  WITH CHECK (auth.uid() = user_id);
