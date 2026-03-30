# 1
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 0 --end 6689 --reset > scan_output.log 2>&1 &

# 2
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 6689 --end 13378 --reset > scan_output.log 2>&1 &

# 3
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 13378 --end 20067 --reset > scan_output.log 2>&1 &

# 4
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 20067 --end 26756 --reset > scan_output.log 2>&1 &

# 5
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 26756 --end 33445 --reset > scan_output.log 2>&1 &

# 6
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 33445 --end 40134 --reset > scan_output.log 2>&1 &

# 7
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 40134 --end 46823 --reset > scan_output.log 2>&1 &

# 8
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 46823 --end 53512 --reset > scan_output.log 2>&1 &

# 9
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start 53512 --end 60205 --reset > scan_output.log 2>&1 &

# watch
watch -n 5 'cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json | python3 -m json.tool'

# tail
tail -f ~/Desktop/Pipeline/scan_output.log

# cat
cat ~/Desktop/Pipeline/tool_mcp_scan/mcp_scan_stats.json | python3 -m json.tool

# storage
cat ~/Desktop/Pipeline/mcp_scan_storage/scanned_entities.json | python3 -m json.tool | head -30

# con -1

# VM1
pkill -f 'python.*run_scan.py'; sleep 1
cd ~/Desktop/Pipeline && source ~/pipeline-env/bin/activate
nohup python tool_mcp_scan/run_scan.py --start -1 --end 6689 > scan_output.log 2>&1 &
