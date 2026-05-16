from flask import Flask, jsonify, render_template_string
import subprocess, json

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Smart Network Defense Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body { font-family: Arial; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; }
    .card { background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 15px; margin: 10px 0; }
    .stat { display: inline-block; margin: 10px 20px; text-align: center; }
    .stat .num { font-size: 2em; color: #58a6ff; font-weight: bold; }
    .alert-row { padding: 8px; border-bottom: 1px solid #30363d; }
    .alert-row.dos { color: #ff7b72; }
    .alert-row.scan { color: #ffa657; }
    .alert-row.icmp { color: #d2a8ff; }
    .blocked { color: #ff7b72; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #21262d; padding: 8px; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #30363d; }
  </style>
</head>
<body>
  <h1>Smart Network Defense System</h1>
  <div class="card">
    <h3>Statistik Real-time</h3>
    <div class="stat"><div class="num">{{ stats.total_packets }}</div>Total Paket</div>
    <div class="stat"><div class="num" style="color:#ff7b72">{{ stats.blocked }}</div>IP Diblokir</div>
    <div class="stat"><div class="num" style="color:#ffa657">{{ stats.alerts }}</div>Total Alert</div>
  </div>

  <div class="card">
    <h3>Log Serangan (IDS Alerts)</h3>
    {% if alerts %}
    <table>
      <tr><th>Waktu</th><th>Tipe Serangan</th><th>IP Sumber</th><th>Detail</th></tr>
      {% for a in alerts[-20:]|reverse %}
      <tr class="alert-row {{ a.type|lower|replace(' ','') }}">
        <td>{{ a.time }}</td>
        <td>{{ a.type }}</td>
        <td class="blocked">{{ a.src_ip }}</td>
        <td>{{ a.detail }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <p style="color:#3fb950">Tidak ada serangan terdeteksi</p>
    {% endif %}
  </div>

  <div class="card">
    <h3>IP yang Diblokir Firewall</h3>
    {% if blocked %}
      {% for ip in blocked %}
        <span class="blocked" style="margin-right:15px">{{ ip }}</span>
      {% endfor %}
    {% else %}
      <p style="color:#3fb950">Tidak ada IP diblokir</p>
    {% endif %}
  </div>
</body>
</html>
"""

# Import controller state (shared via file)
import os, json

def read_state():
    try:
        with open('/tmp/defense_state.json') as f:
            return json.load(f)
    except:
        return {"stats": {"total_packets":0,"blocked":0,"alerts":0},
                "alerts": [], "blocked_ips": []}

@app.route('/')
def index():
    state = read_state()
    return render_template_string(HTML,
        stats=state['stats'],
        alerts=state['alerts'],
        blocked=state['blocked_ips'])

@app.route('/api/state')
def api_state():
    return jsonify(read_state())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
