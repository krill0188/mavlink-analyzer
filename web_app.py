#!/usr/bin/env python3
"""
MAVLink Analyzer — 웹 서버
파일 업로드 → MAVLink 분석 → HTML 보고서 반환 + 히스토리 영구 저장
"""
import os
import sys
import json
import tempfile
import threading
import uuid
import datetime
from pathlib import Path

from flask import Flask, request, jsonify, send_file, render_template_string

BASE_DIR   = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"   # 영구 보고서 저장소
HISTORY_FILE = BASE_DIR / "history.json"  # 분석 히스토리 인덱스
REPORTS_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(BASE_DIR))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB

# 진행 중인 분석 작업 (task_id → status)
_jobs: dict = {}
_jobs_lock  = threading.Lock()
_hist_lock  = threading.Lock()

# ─────────────────────────────────────────────
# 히스토리 관리
# ─────────────────────────────────────────────

def _load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []

def _save_history_entry(entry: dict) -> None:
    with _hist_lock:
        hist = _load_history()
        hist.insert(0, entry)          # 최신순
        hist = hist[:200]              # 최대 200건 보관
        HISTORY_FILE.write_text(
            json.dumps(hist, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

# ─────────────────────────────────────────────
# 업로드 UI (히스토리 포함)
# ─────────────────────────────────────────────

UPLOAD_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MAVLink Analyzer — pcap 분석</title>
<style>
:root{
  --bg:#0a0e1a;--card:#12172a;--card2:#1a2035;--border:#2a3050;
  --text:#e0e6ff;--muted:#7080a0;
  --green:#00ff88;--blue:#4488ff;--red:#ff3366;--orange:#ff8800;--yellow:#ffdd00;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;padding:2rem;}
.page{max-width:900px;margin:0 auto;}
.hero{text-align:center;margin-bottom:2.5rem;}
.hero h1{font-size:2rem;background:linear-gradient(135deg,var(--blue),var(--green));
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem;}
.hero p{color:var(--muted);font-size:1rem;}
.features{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-top:1rem;}
.feat{background:rgba(68,136,255,.1);border:1px solid rgba(68,136,255,.3);
      border-radius:8px;padding:.35rem .8rem;font-size:.8rem;color:var(--blue);}

.dropzone{
  border:2px dashed var(--border);border-radius:16px;
  background:var(--card);padding:3rem 2rem;text-align:center;cursor:pointer;
  transition:all .2s;
}
.dropzone.over{border-color:var(--blue);background:rgba(68,136,255,.08);}
.dropzone svg{width:48px;height:48px;color:var(--muted);margin-bottom:1rem;}
.dropzone h2{font-size:1.1rem;margin-bottom:.4rem;}
.dropzone p{color:var(--muted);font-size:.85rem;margin-bottom:1.2rem;}
#file-input{display:none;}
.btn{display:inline-block;padding:.65rem 2rem;border-radius:8px;border:none;cursor:pointer;
     font-size:.9rem;font-weight:600;background:linear-gradient(135deg,var(--blue),#2266cc);
     color:#fff;transition:opacity .2s;}
.btn:hover{opacity:.85;}

.progress-wrap{display:none;margin-top:1.5rem;}
.progress-bar-bg{background:var(--card);border:1px solid var(--border);border-radius:8px;height:10px;overflow:hidden;margin-bottom:.8rem;}
.progress-bar{height:100%;border-radius:8px;background:linear-gradient(90deg,var(--blue),var(--green));width:0%;transition:width .4s;}
.progress-msg{color:var(--muted);font-size:.88rem;text-align:center;}

.result-wrap{display:none;margin-top:1.5rem;background:var(--card);border:1px solid var(--border);
             border-radius:12px;padding:1.5rem;text-align:center;}
.result-wrap h3{margin-bottom:1rem;color:var(--green);}
.result-wrap a{display:inline-block;padding:.6rem 1.8rem;border-radius:8px;
               background:linear-gradient(135deg,var(--green),#00cc66);
               color:#0a0e1a;font-weight:700;text-decoration:none;font-size:.9rem;margin:.3rem;}
.result-wrap a.json-btn{background:var(--card2);border:1px solid var(--border);color:var(--text);}

.error-msg{display:none;color:var(--red);background:rgba(255,51,102,.1);
           border:1px solid rgba(255,51,102,.3);border-radius:8px;
           padding:.8rem 1.2rem;margin-top:1.2rem;text-align:center;}

/* 히스토리 */
.history-section{margin-top:3rem;}
.history-header{display:flex;justify-content:space-between;align-items:center;
                margin-bottom:1.2rem;border-bottom:1px solid var(--border);padding-bottom:.6rem;}
.history-header h2{font-size:1.1rem;color:var(--blue);}
.hist-btn{background:var(--card2);border:1px solid var(--border);color:var(--muted);
          padding:.3rem .8rem;border-radius:6px;cursor:pointer;font-size:.8rem;}
.hist-btn:hover{border-color:var(--red);color:var(--red);}
.history-empty{text-align:center;color:var(--muted);font-size:.9rem;padding:2rem;}
.hist-item{background:var(--card);border:1px solid var(--border);border-radius:10px;
           padding:1rem 1.2rem;margin-bottom:.8rem;display:flex;
           justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;}
.hist-item:hover{border-color:var(--blue);}
.hist-left{display:flex;align-items:center;gap:.8rem;flex:1;min-width:0;}
.hist-grade{display:inline-block;padding:.2rem .7rem;border-radius:10px;font-size:.75rem;font-weight:700;flex-shrink:0;}
.grade-GREEN {background:rgba(0,255,136,.15);color:var(--green);}
.grade-YELLOW{background:rgba(255,221,0,.15);color:var(--yellow);}
.grade-ORANGE{background:rgba(255,136,0,.15);color:var(--orange);}
.grade-RED   {background:rgba(255,51,102,.15);color:var(--red);}
.hist-info{min-width:0;}
.hist-filename{font-weight:600;font-size:.92rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.hist-meta{color:var(--muted);font-size:.78rem;margin-top:.2rem;}
.hist-stats{display:flex;gap:.8rem;flex-shrink:0;}
.hist-stat{text-align:center;}
.hist-stat .sv{font-size:1rem;font-weight:700;}
.hist-stat .sl{color:var(--muted);font-size:.7rem;}
.hist-actions{display:flex;gap:.5rem;flex-shrink:0;}
.hist-actions a{padding:.35rem .9rem;border-radius:6px;text-decoration:none;font-size:.82rem;font-weight:600;}
.hist-view{background:rgba(68,136,255,.15);color:var(--blue);border:1px solid rgba(68,136,255,.3);}
.hist-view:hover{background:rgba(68,136,255,.3);}
.hist-json{background:var(--card2);color:var(--muted);border:1px solid var(--border);}
.hist-del{background:rgba(255,51,102,.1);color:var(--red);border:1px solid rgba(255,51,102,.2);cursor:pointer;}
.hist-del:hover{background:rgba(255,51,102,.25);}

.footer{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center;}
.footer a{color:var(--blue);text-decoration:none;}
</style>
</head>
<body>
<div class="page">

<div class="hero">
  <h1>MAVLink Analyzer</h1>
  <p>Wireshark pcap 덤프를 업로드하면 드론 통신 분석 보고서를 즉시 생성합니다</p>
  <div class="features">
    <span class="feat">RTT 분석</span>
    <span class="feat">패킷 손실</span>
    <span class="feat">HEARTBEAT 모니터</span>
    <span class="feat">커맨드/ACK 추적</span>
    <span class="feat">이상 탐지</span>
    <span class="feat">조치 가이드</span>
    <span class="feat">비행 궤적 지도</span>
    <span class="feat">히스토리</span>
  </div>
</div>

<div class="dropzone" id="dropzone">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
    <path d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
  </svg>
  <h2>pcap 파일을 드래그하거나 클릭하여 선택</h2>
  <p>.pcap / .pcapng 형식 지원 · 최대 100MB</p>
  <button class="btn" onclick="document.getElementById('file-input').click()">파일 선택</button>
  <input type="file" id="file-input" accept=".pcap,.pcapng,.cap">
</div>

<div class="progress-wrap" id="progress-wrap">
  <div class="progress-bar-bg"><div class="progress-bar" id="progress-bar"></div></div>
  <div class="progress-msg" id="progress-msg">분석 중...</div>
</div>

<div class="result-wrap" id="result-wrap">
  <h3>✅ 분석 완료!</h3>
  <div id="result-links"></div>
</div>

<div class="error-msg" id="error-msg"></div>

<!-- 히스토리 섹션 -->
<div class="history-section">
  <div class="history-header">
    <h2>📋 과거 분석 히스토리</h2>
    <button class="hist-btn" onclick="clearHistory()">전체 삭제</button>
  </div>
  <div id="history-list"><div class="history-empty">로딩 중...</div></div>
</div>

<div class="footer">
  <p>MAVLink v1/v2 · UDP/TCP · ArduPilot & PX4 호환 | <a href="/health">서버 상태</a></p>
</div>

</div><!-- /page -->

<script>
const dropzone    = document.getElementById('dropzone');
const fileInput   = document.getElementById('file-input');
const progressWrap = document.getElementById('progress-wrap');
const progressBar = document.getElementById('progress-bar');
const progressMsg = document.getElementById('progress-msg');
const resultWrap  = document.getElementById('result-wrap');
const errorMsg    = document.getElementById('error-msg');

dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('over'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
dropzone.addEventListener('drop', e => {
  e.preventDefault(); dropzone.classList.remove('over');
  if (e.dataTransfer.files[0]) uploadFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', e => { if (e.target.files[0]) uploadFile(e.target.files[0]); });

let pollTimer = null;

function uploadFile(file) {
  errorMsg.style.display = 'none';
  resultWrap.style.display = 'none';
  progressWrap.style.display = 'block';
  progressBar.style.width = '5%';
  progressMsg.textContent = `📦 업로드 중: ${file.name} (${(file.size/1024/1024).toFixed(1)}MB)`;

  const formData = new FormData();
  formData.append('file', file);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/upload');
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) progressBar.style.width = Math.round(e.loaded/e.total*30)+'%';
  };
  xhr.onload = () => {
    if (xhr.status === 200) {
      const res = JSON.parse(xhr.responseText);
      if (res.task_id) { progressMsg.textContent = '🔍 MAVLink 패킷 파싱 중...'; progressBar.style.width='35%'; pollStatus(res.task_id); }
      else showError('서버 오류: task_id 없음');
    } else {
      try { showError(JSON.parse(xhr.responseText).error || '업로드 실패'); } catch { showError('업로드 실패: '+xhr.status); }
    }
  };
  xhr.onerror = () => showError('네트워크 오류');
  xhr.send(formData);
}

function pollStatus(taskId) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const res  = await fetch('/status/'+taskId);
      const data = await res.json();
      const pctMap = {parsing:40,latency:55,loss:65,anomaly:75,report:90};
      progressBar.style.width = (pctMap[data.step]||40)+'%';
      progressMsg.textContent = '🔍 '+(data.message||'분석 중...');
      if (data.status === 'done') {
        progressBar.style.width='100%'; progressMsg.textContent='✅ 완료!';
        setTimeout(() => { showResult(taskId, data); loadHistory(); }, 400);
      } else if (data.status === 'error') {
        showError(data.message||'분석 오류');
      } else {
        pollStatus(taskId);
      }
    } catch { pollStatus(taskId); }
  }, 1000);
}

function showResult(taskId, data) {
  progressWrap.style.display = 'none';
  resultWrap.style.display = 'block';
  document.getElementById('result-links').innerHTML = `
    <a href="/report/${taskId}/html" target="_blank">📊 HTML 보고서 열기</a>
    <a href="/report/${taskId}/json" class="json-btn" target="_blank">📄 JSON 다운로드</a>
    <br><br>
    <small style="color:var(--muted)">
      총 패킷: ${(data.total_frames||0).toLocaleString()} ·
      MAVLink: ${(data.mavlink_messages||0).toLocaleString()} ·
      이상 이벤트: ${data.anomalies||0}
    </small>
  `;
}

function showError(msg) {
  progressWrap.style.display = 'none';
  errorMsg.textContent = '❌ '+msg;
  errorMsg.style.display = 'block';
}

// ──────────────────────────────────────
// 히스토리
// ──────────────────────────────────────
async function loadHistory() {
  const list = document.getElementById('history-list');
  try {
    const res  = await fetch('/api/history');
    const hist = await res.json();
    if (!hist.length) {
      list.innerHTML = '<div class="history-empty">분석 기록이 없습니다. pcap 파일을 업로드하면 여기에 표시됩니다.</div>';
      return;
    }
    list.innerHTML = hist.map(h => `
      <div class="hist-item" id="hi-${h.task_id}">
        <div class="hist-left">
          <span class="hist-grade grade-${h.grade}">${h.grade}</span>
          <div class="hist-info">
            <div class="hist-filename" title="${h.filename}">${h.filename}</div>
            <div class="hist-meta">${h.analyzed_at} · ${h.duration} · ${(h.total_frames||0).toLocaleString()}패킷 · MAVLink ${(h.mavlink_messages||0).toLocaleString()}건</div>
          </div>
        </div>
        <div class="hist-stats">
          <div class="hist-stat">
            <div class="sv" style="color:${anomalyColor(h.anomalies)}">${h.anomalies}</div>
            <div class="sl">이상</div>
          </div>
          <div class="hist-stat">
            <div class="sv">${h.mean_rtt ? h.mean_rtt.toFixed(0)+'ms' : '—'}</div>
            <div class="sl">RTT</div>
          </div>
        </div>
        <div class="hist-actions">
          <a href="/report/${h.task_id}/html" target="_blank" class="hist-view">보고서</a>
          <a href="/report/${h.task_id}/json" class="hist-json">JSON</a>
          <button class="hist-del" onclick="deleteEntry('${h.task_id}')">삭제</button>
        </div>
      </div>
    `).join('');
  } catch (e) {
    list.innerHTML = '<div class="history-empty" style="color:var(--red)">히스토리 로드 오류</div>';
  }
}

function anomalyColor(n) {
  return n === 0 ? 'var(--green)' : n < 3 ? 'var(--yellow)' : n < 6 ? 'var(--orange)' : 'var(--red)';
}

async function deleteEntry(taskId) {
  if (!confirm('이 분석 기록을 삭제할까요?')) return;
  await fetch('/api/history/'+taskId, { method: 'DELETE' });
  loadHistory();
}

async function clearHistory() {
  if (!confirm('모든 분석 기록을 삭제할까요? (보고서 파일도 함께 삭제됩니다)')) return;
  await fetch('/api/history', { method: 'DELETE' });
  loadHistory();
}

// 페이지 로드 시 히스토리 표시
loadHistory();
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────
# 라우트
# ─────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template_string(UPLOAD_HTML)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "mavlink-analyzer"})


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "파일이 없습니다"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "파일명 없음"}), 400

    ext = Path(f.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        return jsonify({"error": f"지원하지 않는 형식: {ext}"}), 400

    task_id = str(uuid.uuid4())
    orig_name = Path(f.filename).name

    # pcap 임시 저장
    tmp_dir = Path(tempfile.gettempdir()) / "mavlink_upload"
    tmp_dir.mkdir(exist_ok=True)
    pcap_path = tmp_dir / f"{task_id}{ext}"
    f.save(str(pcap_path))

    with _jobs_lock:
        _jobs[task_id] = {
            "status": "running",
            "step":    "parsing",
            "message": "MAVLink 패킷 파싱 중...",
            "orig_name": orig_name,
        }

    t = threading.Thread(target=_run_analysis, args=(task_id, pcap_path, orig_name), daemon=True)
    t.start()

    return jsonify({"task_id": task_id})


def _run_analysis(task_id: str, pcap_path: Path, orig_name: str):
    """백그라운드 분석 실행 후 REPORTS_DIR에 영구 저장"""
    import time

    def _update(step, msg):
        with _jobs_lock:
            _jobs[task_id].update({"step": step, "message": msg})

    try:
        from analyze import run_analysis
        from report.generator import ReportGenerator

        _update("parsing", "pcap 로드 중...")

        _steps = [
            (4,  "latency", "RTT 분석 중..."),
            (8,  "loss",    "패킷 손실 계산 중..."),
            (12, "anomaly", "이상 탐지 중..."),
            (18, "report",  "보고서 생성 준비 중..."),
        ]
        _step_idx  = [0]
        _done_flag = [False]

        def _ticker():
            t0 = time.time()
            while not _done_flag[0]:
                elapsed = time.time() - t0
                for i, (sec, step, msg) in enumerate(_steps):
                    if elapsed >= sec and _step_idx[0] <= i:
                        _update(step, msg)
                        _step_idx[0] = i + 1
                time.sleep(1)

        threading.Thread(target=_ticker, daemon=True).start()

        result     = run_analysis(pcap_path, quiet=True)
        _done_flag[0] = True

        _update("report", "HTML 보고서 생성 중...")
        gen = ReportGenerator(result)

        html_path = REPORTS_DIR / f"{task_id}.html"
        json_path = REPORTS_DIR / f"{task_id}.json"
        gen.to_html(html_path)
        gen.to_json(json_path)

        # 히스토리 메타 기록
        from core.constants import grade_rtt
        overall = gen._compute_overall_grade()
        entry = {
            "task_id":        task_id,
            "filename":       orig_name,
            "analyzed_at":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "grade":          overall,
            "total_frames":   result.pcap_meta.total_frames,
            "mavlink_messages": result.pcap_meta.mavlink_messages,
            "duration":       result.pcap_meta.duration_str,
            "mean_rtt":       result.latency.mean_rtt_ms,
            "anomalies":      len(result.anomalies),
            "loss_streams":   len(result.loss),
        }
        _save_history_entry(entry)

        with _jobs_lock:
            _jobs[task_id].update({
                "status":           "done",
                "step":             "done",
                "message":          "분석 완료",
                "total_frames":     result.pcap_meta.total_frames,
                "mavlink_messages": result.pcap_meta.mavlink_messages,
                "anomalies":        len(result.anomalies),
            })

    except Exception as e:
        _done_flag[0] = True
        with _jobs_lock:
            _jobs[task_id].update({
                "status":  "error",
                "message": f"분석 오류: {str(e)[:300]}",
            })
    finally:
        try:
            pcap_path.unlink()
        except Exception:
            pass


@app.route("/status/<task_id>", methods=["GET"])
def status(task_id: str):
    with _jobs_lock:
        job = _jobs.get(task_id)
    if not job:
        return jsonify({"error": "작업 없음"}), 404
    exclude = {"pcap_path", "html_path", "json_path"}
    return jsonify({k: v for k, v in job.items() if k not in exclude})


# ─── 보고서 서빙 (영구 저장소) ───────────────

@app.route("/report/<task_id>/html", methods=["GET"])
def report_html(task_id: str):
    p = REPORTS_DIR / f"{task_id}.html"
    if not p.exists():
        return "보고서가 없습니다. 삭제되었거나 아직 분석 중입니다.", 404
    return send_file(str(p), mimetype="text/html")


@app.route("/report/<task_id>/json", methods=["GET"])
def report_json(task_id: str):
    p = REPORTS_DIR / f"{task_id}.json"
    if not p.exists():
        return jsonify({"error": "JSON 없음"}), 404
    return send_file(str(p), mimetype="application/json",
                     as_attachment=True,
                     download_name=f"mavlink_{task_id[:8]}.json")


# ─── 구버전 /result 경로 호환 유지 ───────────

@app.route("/result/<task_id>/html", methods=["GET"])
def result_html_compat(task_id: str):
    return report_html(task_id)


@app.route("/result/<task_id>/json", methods=["GET"])
def result_json_compat(task_id: str):
    return report_json(task_id)


# ─── 히스토리 API ────────────────────────────

@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify(_load_history())


@app.route("/api/history/<task_id>", methods=["DELETE"])
def api_history_delete(task_id: str):
    """단건 삭제 (히스토리 + 보고서 파일)"""
    with _hist_lock:
        hist = _load_history()
        hist = [h for h in hist if h["task_id"] != task_id]
        HISTORY_FILE.write_text(
            json.dumps(hist, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    for ext in (".html", ".json"):
        p = REPORTS_DIR / f"{task_id}{ext}"
        try:
            p.unlink()
        except Exception:
            pass
    return jsonify({"ok": True})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    """전체 삭제"""
    with _hist_lock:
        HISTORY_FILE.write_text("[]", encoding="utf-8")
    for p in REPORTS_DIR.glob("*.html"):
        try: p.unlink()
        except Exception: pass
    for p in REPORTS_DIR.glob("*.json"):
        try: p.unlink()
        except Exception: pass
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7788))
    app.run(host="0.0.0.0", port=port, debug=False)
