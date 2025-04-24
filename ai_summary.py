# Stub for ai_summary.py
import json, requests
def get_summary(path, api_key):
    text = open(path,'r',errors='ignore').read()[:10000]
    prompt = f"You are a system diagnostics expert. Summarize “{path}” in 3–5 sentences."
    payload = {"model":"deepseek/deepseek-r1-zero:free",
               "messages":[{"role":"user","content":prompt+"\n\n"+text}]}
    headers = {"Authorization":f"Bearer {api_key}","Content-Type":"application/json"}
    r = requests.post("https://openrouter.ai/api/v1/chat/completions",
                      headers=headers, data=json.dumps(payload), timeout=30)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()
