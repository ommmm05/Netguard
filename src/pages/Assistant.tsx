import { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Cpu, User, Shield, RefreshCw } from 'lucide-react';
import { API_BASE, apiFetch } from '../api/config';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

const initialMessage = {
  role: 'assistant' as const,
  content: "Hello, I'm the NetGuard AI Analyst Assistant. I have full visibility into your current threat landscape. How can I help you investigate today's incidents? You can ask me about specific alerts, hosts, attack patterns, or request a forensic analysis."
};

function getResponse(): string {
  return "The NetGuard backend AI is currently offline or unreachable. Please start `run_backend.py` to enable full LLM-driven incident analysis.";
}

function formatContent(content: string) {
  const lines = content.split('\n');
  return lines.map((line, i) => {
    if (line.startsWith('**') && line.endsWith('**') && !line.includes(' ')) {
      return <h4 key={i} className="font-bold text-white mt-2 mb-1">{line.replace(/\*\*/g, '')}</h4>;
    }
    const formatted = line
      .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
      .replace(/`([^`]+)`/g, '<code class="bg-slate-700/60 text-cyan-400 px-1 py-0.5 rounded text-xs font-mono">$1</code>');
    if (line.startsWith('- ') || line.startsWith('* ')) {
      return <li key={i} className="ml-4 list-disc text-slate-300" dangerouslySetInnerHTML={{ __html: formatted.replace(/^[-*] /, '') }} />;
    }
    if (/^\d+\./.test(line)) {
      return <li key={i} className="ml-4 list-decimal text-slate-300" dangerouslySetInnerHTML={{ __html: formatted.replace(/^\d+\. /, '') }} />;
    }
    if (line.trim() === '') return <div key={i} className="h-1" />;
    return <p key={i} className="text-slate-300 leading-relaxed" dangerouslySetInnerHTML={{ __html: formatted }} />;
  });
}

const quickPrompts = [
  "What is the most critical alert?",
  "Explain the C2 beacon",
  "What is lateral movement?",
  "How does passive scanning work?",
  "What is SHAP?",
  "Show me all critical alerts",
];

export default function Assistant() {
  const [messages, setMessages] = useState<Message[]>([
    { ...initialMessage, timestamp: new Date().toLocaleTimeString() }
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const sendMessage = (text?: string) => {
    const msg = text || input.trim();
    if (!msg) return;
    const userMsg: Message = { role: 'user', content: msg, timestamp: new Date().toLocaleTimeString() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);
    (async () => {
      try {
        const r = await apiFetch(`${API_BASE}/api/forensics/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msg, history: [] }),
        });
        if (r.ok) {
          const j = (await r.json()) as { reply?: string };
          const assistantMsg: Message = {
            role: 'assistant',
            content: j.reply || 'No reply.',
            timestamp: new Date().toLocaleTimeString(),
          };
          setMessages((prev) => [...prev, assistantMsg]);
          setIsTyping(false);
          return;
        }
      } catch { /* local */ }
      setTimeout(() => {
        const response = getResponse();
        const assistantMsg: Message = { role: 'assistant', content: response, timestamp: new Date().toLocaleTimeString() };
        setMessages((prev) => [...prev, assistantMsg]);
        setIsTyping(false);
      }, 500 + Math.random() * 400);
    })();
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 p-4 md:px-6 md:pt-6 pb-0">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <MessageSquare className="w-5 h-5 text-cyan-400" /> AI Analyst Assistant
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Powered by <span className="text-purple-400 font-mono">chat_service.py</span> · LLM + NetGuard threat context
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 bg-[#111827] border border-[#243244] rounded-lg px-2.5 py-1.5">
              <div className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-xs text-slate-300 font-mono">API connected</span>
            </div>
            <button onClick={() => setMessages([{ ...initialMessage, timestamp: new Date().toLocaleTimeString() }])} className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 rounded-lg">
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Quick prompts */}
        <div className="flex gap-2 overflow-x-auto pb-3">
          {quickPrompts.map(p => (
            <button key={p} onClick={() => sendMessage(p)}
              className="flex-shrink-0 text-xs px-3 py-1.5 bg-slate-800/80 border border-slate-700/60 text-slate-300 hover:text-white hover:border-cyan-500/40 rounded-full transition-all">
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto px-4 md:px-6 py-2 space-y-4">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${msg.role === 'assistant' ? 'bg-[#06B6D4]/20 border border-[#06B6D4]/40' : 'bg-[#111827] border border-[#243244]'}`}>
              {msg.role === 'assistant' ? <Shield className="w-4 h-4 text-white" /> : <User className="w-4 h-4 text-slate-300" />}
            </div>
            <div className={`flex-1 max-w-3xl ${msg.role === 'user' ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
              <div className={`px-4 py-3 rounded-lg text-sm space-y-1 ${
                msg.role === 'assistant'
                  ? 'bg-[#111827] border border-[#243244] text-slate-300'
                  : 'bg-[#06B6D4]/10 border border-[#06B6D4]/20 text-slate-200'
              }`}>
                {msg.role === 'assistant' ? (
                  <div className="space-y-1">{formatContent(msg.content)}</div>
                ) : (
                  <p>{msg.content}</p>
                )}
              </div>
              <div className={`flex items-center gap-1.5 text-xs text-slate-500 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                {msg.role === 'assistant' && <Cpu className="w-3 h-3" />}
                <span className="font-mono">{msg.timestamp}</span>
                <span>{msg.role === 'assistant' ? '· NetGuard AI' : '· You'}</span>
              </div>
            </div>
          </div>
        ))}

        {isTyping && (
          <div className="flex gap-3">
            <div className="flex-shrink-0 w-8 h-8 rounded-full bg-[#06B6D4]/20 border border-[#06B6D4]/40 flex items-center justify-center">
              <Shield className="w-4 h-4 text-[#06B6D4]" />
            </div>
            <div className="px-4 py-3 bg-[#111827] border border-[#243244] rounded-lg">
              <div className="flex gap-1.5 items-center">
                <span className="w-2 h-2 rounded-full bg-[#06B6D4] animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-2 h-2 rounded-full bg-[#06B6D4] animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-2 h-2 rounded-full bg-[#06B6D4] animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex-shrink-0 p-4 md:px-6 md:pb-6 border-t border-[#243244]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
            placeholder="Ask about alerts, attacks, hosts, or forensics..."
            className="flex-1 bg-[#0F172A] border border-[#243244] rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-[#06B6D4]/60 focus:ring-1 focus:ring-[#06B6D4]/20"
          />
          <button
            onClick={() => sendMessage()}
            disabled={!input.trim() || isTyping}
            className="px-4 py-2.5 bg-[#06B6D4] hover:bg-[#0891B2] disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center gap-2"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
        <p className="text-xs text-slate-600 mt-2 text-center">chat_service.py · Context-aware threat investigation · Try: "Explain the C2 beacon"</p>
      </div>
    </div>
  );
}
