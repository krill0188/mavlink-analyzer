#!/bin/bash
# MAVLink Analyzer — ngrok 실행 + URL 텔레그램 알림
BOT_TOKEN="8628562151:AAGS7fCabXsrm6KFVOw0SJ_aCKuqrb1NT-s"
CHAT_ID="382773750"

# 기존 ngrok 종료
pkill -f "ngrok http 7788" 2>/dev/null
sleep 1

# ngrok 백그라운드 실행
/usr/local/bin/ngrok http 7788 --log=stdout >> /tmp/mavlink_ngrok.log 2>&1 &

# URL 확인 (최대 30초 대기)
URL=""
for i in $(seq 1 15); do
    sleep 2
    URL=$(/usr/bin/curl -s --ipv4 http://localhost:4040/api/tunnels 2>/dev/null | \
        /usr/bin/python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    urls = [t['public_url'] for t in d.get('tunnels', []) if t.get('proto') == 'https']
    print(urls[0] if urls else '')
except: print('')
" 2>/dev/null)
    if [ -n "$URL" ]; then
        break
    fi
done

# 텔레그램 알림
if [ -n "$URL" ]; then
    MSG="🚁 MAVLink Analyzer (Mac 서버) 가동
🔗 URL: ${URL}
📊 pcap 파일 업로드 → 드론 통신 분석 보고서
⚡ Render.com 대비 고속 분석"

    /usr/bin/curl -s --ipv4 \
        "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${CHAT_ID}" \
        --data-urlencode "text=${MSG}" \
        > /dev/null 2>&1
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ngrok URL: ${URL}" >> /tmp/mavlink_ngrok.log
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ngrok URL 획득 실패" >> /tmp/mavlink_ngrok.log
fi

# ngrok 프로세스 종료 대기 (launchd KeepAlive 유지)
wait
