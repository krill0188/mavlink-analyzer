#!/usr/bin/env python3
"""
MAVLink Analyzer — 웹 서버
파일 업로드 → MAVLink 분석 → HTML 보고서 반환
"""
import os
import sys
import tempfile
import threading
import uuid
from pathlib import Path

from flask import Flask, request, jsonify, send_file, render_template_string

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB

# 진행 중인 분석 작업 (task_id → status)
_jobs: dict = {}
_jobs_lock = threading.Lock()

# ─────────────────────────────────────────────
# 업로드 UI
# ─────────────────────────────────────────────

UPLOAD_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MAVLink Analyzer — pcap 분석</title>
<style>
:root{
  --bg:#0a0e1a;--card:#12172a;--border:#2a3050;
  --text:#e0e6ff;--muted:#7080a0;
  --green:#00ff88;--blue:#4488ff;--red:#ff3366;--orange:#ff8800;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;
     min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem;}
.hero{text-align:center;margin-bottom:2.5rem;}
.hero h1{font-size:2rem;background:linear-gradient(135deg,var(--blue),var(--green));
          -webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem;}
.hero p{color:var(--muted);font-size:1rem;}
.features{display:flex;gap:1.2rem;justify-content:center;flex-wrap:wrap;margin-top:1rem;}
.feat{background:rgba(68,136,255,.1);border:1px solid rgba(68,136,255,.3);
      border-radius:8px;padding:.4rem .9rem;font-size:.82rem;color:var(--blue);}

.dropzone{
  width:100%;max-width:640px;
  border:2px dashed var(--border);border-radius:16px;
  background:var(--card);
  padding:3rem 2rem;text-align:center;cursor:pointer;
  transition:all .2s;position:relative;
}
.dropzone.over{border-color:var(--blue);background:rgba(68,136,255,.08);}
.dropzone svg{width:56px;height:56px;color:var(--muted);margin-bottom:1rem;}
.dropzone h2{font-size:1.15rem;margin-bottom:.4rem;}
.dropzone p{color:var(--muted);font-size:.88rem;margin-bottom:1.2rem;}
#file-input{display:none;}
.btn{
  display:inline-block;padding:.65rem 2rem;border-radius:8px;
  border:none;cursor:pointer;font-size:.95rem;font-weight:600;
  background:linear-gradient(135deg,var(--blue),#2266cc);
  color:#fff;transition:opacity .2s;
}
.btn:hover{opacity:.85;}
.btn:disabled{opacity:.4;cursor:not-allowed;}

.progress-wrap{display:none;width:100%;max-width:640px;margin-top:1.5rem;}
.progress-bar-bg{background:var(--card);border:1px solid var(--border);border-radius:8px;
                 height:10px;overflow:hidden;margin-bottom:.8rem;}
.progress-bar{height:100%;border-radius:8px;
              background:linear-gradient(90deg,var(--blue),var(--green));
              width:0%;transition:width .4s;}
.progress-msg{color:var(--muted);font-size:.88rem;text-align:center;}

.result-wrap{display:none;width:100%;max-width:640px;margin-top:1.5rem;
             background:var(--card);border:1px solid var(--border);border-radius:12px;
             padding:1.5rem;text-align:center;}
.result-wrap h3{margin-bottom:1rem;color:var(--green);}
.result-wrap a{
  display:inline-block;padding:.65rem 2rem;border-radius:8px;
  background:linear-gradient(135deg,var(--green),#00cc66);
  color:#0a0e1a;font-weight:700;text-decoration:none;font-size:.95rem;
  margin:.3rem;
}
.result-wrap a.json-btn{background:var(--card);border:1px solid var(--border);color:var(--text);}

.error-msg{display:none;color:var(--red);background:rgba(255,51,102,.1);
           border:1px solid rgba(255,51,102,.3);border-radius:8px;
           padding:.8rem 1.2rem;margin-top:1.2rem;width:100%;max-width:640px;text-align:center;}

.footer{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center;}
.footer a{color:var(--blue);text-decoration:none;}

.limit-note{color:var(--muted);font-size:.78rem;margin-top:.5rem;}
</style>
</head>
<body>
<div class="hero">
  <h1>MAVLink Analyzer</h1>
  <p>Wireshark pcap 덤프를 업로드하면 드론 통신 분석 보고서를 즉시 생성합니다</p>
  <div class="features">
    <span class="feat">RTT 분석</span>
    <span class="feat">패킷 손실</span>
    <span class="feat">HEARTBEAT 모니터</span>
    <span class="feat">커맨드/ACK 추적</span>
    <span class="feat">이상 탐지</span>
    <span class="feat">비행 궤적 지도</span>
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
  <p class="limit-note">분석 시간: 파일 크기에 따라 10초~3분 소요</p>
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

<div class="footer">
  <p>MAVLink v1/v2 · UDP/TCP · ArduPilot & PX4 호환 |
     <a href="/health">서버 상태</a></p>
</div>

<script>
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const progressWrap = document.getElementById('progress-wrap');
const progressBar = document.getElementById('progress-bar');
const progressMsg = document.getElementById('progress-msg');
const resultWrap = document.getElementById('result-wrap');
const errorMsg = document.getElementById('error-msg');

// 드래그앤드롭
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('over'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
dropzone.addEventListener('drop', e => {
  e.preventDefault(); dropzone.classList.remove('over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
});
fileInput.addEventListener('change', e => {
  if (e.target.files[0]) uploadFile(e.target.files[0]);
});

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

  // 업로드 진행
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) {
      const pct = Math.round(e.loaded / e.total * 30);
      progressBar.style.width = pct + '%';
    }
  };

  xhr.onload = () => {
    if (xhr.status === 200) {
      const res = JSON.parse(xhr.responseText);
      if (res.task_id) {
        progressMsg.textContent = '🔍 MAVLink 패킷 파싱 중...';
        progressBar.style.width = '35%';
        pollStatus(res.task_id);
      } else {
        showError('서버 오류: task_id 없음');
      }
    } else {
      try {
        const err = JSON.parse(xhr.responseText);
        showError(err.error || '업로드 실패');
      } catch { showError('업로드 실패: ' + xhr.status); }
    }
  };
  xhr.onerror = () => showError('네트워크 오류');
  xhr.send(formData);
}

function pollStatus(taskId) {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    try {
      const res = await fetch('/status/' + taskId);
      const data = await res.json();

      const steps = ['패킷 파싱', '스트림 식별', 'RTT 분석', '손실 계산', '이상 탐지', '보고서 생성'];
      const pctMap = { parsing: 40, endpoint: 55, latency: 65, loss: 75, anomaly: 85, report: 95 };
      const pct = pctMap[data.step] || 40;
      progressBar.style.width = pct + '%';
      progressMsg.textContent = '🔍 ' + (data.message || '분석 중...');

      if (data.status === 'done') {
        progressBar.style.width = '100%';
        progressMsg.textContent = '✅ 완료!';
        setTimeout(() => showResult(taskId, data), 400);
      } else if (data.status === 'error') {
        showError(data.message || '분석 오류');
      } else {
        pollStatus(taskId);  // 계속 폴링
      }
    } catch (e) {
      pollStatus(taskId);
    }
  }, 1000);
}

function showResult(taskId, data) {
  progressWrap.style.display = 'none';
  resultWrap.style.display = 'block';
  const links = document.getElementById('result-links');
  links.innerHTML = `
    <a href="/result/${taskId}/html" target="_blank">📊 HTML 보고서 열기</a>
    <a href="/result/${taskId}/json" class="json-btn" target="_blank">📄 JSON 다운로드</a>
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
  errorMsg.textContent = '❌ ' + msg;
  errorMsg.style.display = 'block';
}
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

    # 임시 파일로 저장
    tmp_dir = Path(tempfile.gettempdir()) / "mavlink_analyzer"
    tmp_dir.mkdir(exist_ok=True)
    pcap_path = tmp_dir / f"{task_id}{ext}"
    f.save(str(pcap_path))

    # 초기 상태
    with _jobs_lock:
        _jobs[task_id] = {
            "status": "running",
            "step": "parsing",
            "message": "MAVLink 패킷 파싱 중...",
            "pcap_path": str(pcap_path),
        }

    # 백그라운드 분석
    t = threading.Thread(target=_run_analysis, args=(task_id, pcap_path), daemon=True)
    t.start()

    return jsonify({"task_id": task_id})


def _run_analysis(task_id: str, pcap_path: Path):
    """백그라운드 분석 실행"""
    try:
        from analyze import run_analysis
        from report.generator import ReportGenerator

        def _update(step, msg):
            with _jobs_lock:
                _jobs[task_id].update({"step": step, "message": msg})

        _update("parsing", "MAVLink 패킷 파싱 중...")
        result = run_analysis(pcap_path, quiet=True)

        _update("report", "HTML 보고서 생성 중...")
        gen = ReportGenerator(result)

        out_dir = Path(tempfile.gettempdir()) / "mavlink_analyzer"
        html_path = out_dir / f"{task_id}.html"
        json_path = out_dir / f"{task_id}.json"
        gen.to_html(html_path)
        gen.to_json(json_path)

        with _jobs_lock:
            _jobs[task_id].update({
                "status": "done",
                "step": "done",
                "message": "분석 완료",
                "html_path": str(html_path),
                "json_path": str(json_path),
                "total_frames": result.pcap_meta.total_frames,
                "mavlink_messages": result.pcap_meta.mavlink_messages,
                "anomalies": len(result.anomalies),
            })

        # pcap 임시 파일 삭제
        try:
            pcap_path.unlink()
        except Exception:
            pass

    except Exception as e:
        import traceback
        with _jobs_lock:
            _jobs[task_id].update({
                "status": "error",
                "message": f"분석 오류: {str(e)[:200]}",
            })


@app.route("/status/<task_id>", methods=["GET"])
def status(task_id: str):
    with _jobs_lock:
        job = _jobs.get(task_id)
    if not job:
        return jsonify({"error": "작업 없음"}), 404
    return jsonify({k: v for k, v in job.items() if k not in ("pcap_path", "html_path", "json_path")})


@app.route("/result/<task_id>/html", methods=["GET"])
def result_html(task_id: str):
    with _jobs_lock:
        job = _jobs.get(task_id)
    if not job or job.get("status") != "done":
        return "보고서 없음 (분석 중이거나 오류)", 404
    html_path = Path(job["html_path"])
    if not html_path.exists():
        return "파일 없음", 404
    return send_file(str(html_path), mimetype="text/html")


@app.route("/result/<task_id>/json", methods=["GET"])
def result_json(task_id: str):
    with _jobs_lock:
        job = _jobs.get(task_id)
    if not job or job.get("status") != "done":
        return jsonify({"error": "보고서 없음"}), 404
    json_path = Path(job["json_path"])
    if not json_path.exists():
        return jsonify({"error": "파일 없음"}), 404
    return send_file(str(json_path), mimetype="application/json",
                     as_attachment=True, download_name=f"mavlink_report_{task_id[:8]}.json")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7788))
    app.run(host="0.0.0.0", port=port, debug=False)
