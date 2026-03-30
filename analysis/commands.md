# per liberare memoria
df -h /
du -h --max-depth=3 ~ | sort -rh | head -50
E poi passare il risultato a Claude 

# per riavviare le macchine
ssh-keygen -R 10.79.6.134

# per liberare la memoria sempre
nohup bash -c 'while true; do rm -rf ~/go/pkg ~/.cache/uv ~/.cache/pip ~/.cache/camoufox ~/.cache/selenium ~/.cache/pnpm ~/.cache/puccinialin ~/.cache/ffmpeg-static-nodejs ~/.cache/prisma ~/.cache/node-gyp ~/.cache/huggingface ~/.npm ~/.rustup ~/.bun ~/.config/google-chrome-for-testing /tmp/camoufox-* /tmp/node-gyp-* /tmp/phantomjs /tmp/nx-native-file-cache-* /tmp/v8-compile-cache-* /tmp/ncc-cache /tmp/node-compile-cache /tmp/bunx-* 2>/dev/null; sleep 1800; done' > /dev/null 2>&1 &
# per killare il processo alla fine
pkill -f "while true; do rm -rf"

# per eliminare la cache di go
sudo rm -rf ~/go/pkg