import click
import re
from rich.console import Console
from openai import OpenAI
import instructor

from autopenbench.utils import load_data, load_milestones
from autopenbench.driver import PentestDriver
from autopenbench.evaluation import Evaluator
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect

# Hãy cung cấp API key của bạn ở đây
OPENAI_KEY = 'sk-...' 


def parse_log_file(log_path: str):
    """
    Hàm này đọc và phân tích file log do VulnBot tạo ra.
    Nó trích xuất các cặp (lệnh, kết quả).
    Định dạng log kỳ vọng: Bắt đầu bằng "Action:" và theo sau là "Observation:"
    """
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file log tại '{log_path}'")
        return []

    # Sử dụng regex để tìm tất cả các khối Action/Observation
    # (?s) cho phép '.' khớp với cả ký tự xuống dòng
    pattern = re.compile(r"Action:(.*?)\nObservation:(.*?)(?=\nAction:|\Z)", re.DOTALL)
    matches = pattern.findall(content)
    
    steps = []
    for command, output in matches:
        steps.append({
            "command": command.strip(),
            "output": output.strip()
        })
    return steps

def command_to_action(command_str: str, kali_ip: str):
    """
    Chuyển đổi một chuỗi lệnh từ log thành một đối tượng Tool của benchmark.
    """
    command_lower = command_str.lower()
    
    # Ưu tiên các lệnh đặc biệt trước
    if command_lower.startswith("submit"):
        # Ví dụ: "submit flag{this_is_a_test}"
        flag = command_str.split(" ", 1)[1]
        return FinalAnswer(answer=flag)
    
    if command_lower.startswith("ssh"):
        # Ví dụ: "ssh user@192.168.2.4 -p mypassword" (cần phân tích phức tạp hơn nếu cần)
        # Đây là ví dụ đơn giản
        try:
            parts = command_str.split()
            user_host = parts[1]
            user, host = user_host.split('@')
            # Giả định mật khẩu nếu có
            password = parts[3] if len(parts) > 3 and parts[2] == '-p' else ""
            return SSHConnect(machine_ipaddr=host, user=user, psw=password)
        except:
            # Nếu không phân tích được, coi như lệnh bash thường
            pass

    # Mặc định, tất cả các lệnh khác đều là ExecuteBash trên máy Kali
    return ExecuteBash(machine_ipaddr=kali_ip, cmd=command_str)



@click.command()
@click.option('--log-file', default='vulnbot.log', help='Đường dẫn đến file log của VulnBot.')
@click.option('--test-case', default='access_control', help='Tên bài test (ví dụ: access_control, web_security).')
@click.option('--test-index', default=0, type=int, help='Chỉ số của bài test trong bộ test case.')
def main(log_file, test_case, test_index):
    """
    Script này đọc một file log, tái hiện các hành động và đánh giá hiệu suất
    của agent dựa trên các milestones được định sẵn.
    """
    console = Console()
    console.print(f"Bắt đầu quá trình đánh giá từ file log: [bold cyan]{log_file}[/bold cyan]", style="bold green")

    # 1. Khởi tạo Môi trường Benchmark
    try:
        game = load_data('in-vitro')[test_case][test_index]
        driver = PentestDriver(game['task'], game['flag'], game['target'])
        driver.reset() # Khởi động các container Docker
        console.print(f"Đã khởi tạo môi trường cho bài test: [bold yellow]{game['task']}[/bold yellow]")
    except Exception as e:
        console.print(f"Lỗi khi khởi tạo môi trường benchmark: {e}", style="bold red")
        return

    # 2. Khởi tạo Người đánh giá (Evaluator)
    try:
        command_milestones = load_milestones('command', 'in-vitro', test_case, test_index)
        stage_milestones = load_milestones('stage', 'in-vitro', test_case, test_index)
        evaluator = Evaluator(OPENAI_KEY, command_milestones, stage_milestones)
        console.print("Đã khởi tạo Evaluator với các milestones.", style="green")
    except Exception as e:
        console.print(f"Lỗi khi khởi tạo Evaluator: {e}. Hãy kiểm tra OpenAI API key.", style="bold red")
        driver.close()
        return

    # 3. Đọc và Phân tích File Log
    log_steps = parse_log_file(log_file)
    if not log_steps:
        console.print("Không có hành động nào được tìm thấy trong file log. Kết thúc.", style="yellow")
        driver.close()
        return

    console.print(f"Đã phân tích được [bold]{len(log_steps)}[/bold] bước từ file log.")
    
    # 4. Tái hiện và Đánh giá từng bước
    done = False
    for i, step_data in enumerate(log_steps):
        if done:
            break
        
        console.print(f"\n--- Bước {i+1}/{len(log_steps)} ---", style="bold blue")
        
        command_from_log = step_data['command']
        console.print(f"Hành động từ Log: [dim]{command_from_log}[/dim]")
        
        # Chuyển đổi lệnh thành hành động của benchmark
        action = command_to_action(command_from_log, driver.kali_instance_ip)
        
        # Gửi hành động cho driver để thực thi trong môi trường benchmark
        observation, done = driver.step(action)
        
        # Tạo chuỗi `step` để đưa cho evaluator
        evaluation_input = f"Action: {action}\nObservation: {observation}"
        
        console.print("Đang gọi API để đánh giá bước đi...")
        evaluator.evaluate_step(evaluation_input)
        
        # In ra các milestones đã hoàn thành
        console.print("Các Milestones đã hoàn thành:", style="bold green")
        for ms, completed in evaluator.command_milestones_completed.items():
            if completed:
                console.print(f"- {ms}")
        
    # 5. Dọn dẹp và Báo cáo cuối cùng
    console.print("\n--- KẾT QUẢ ĐÁNH GIÁ CUỐI CÙNG ---", style="bold magenta")
    evaluator.show_score()
    
    driver.close()
    console.print("Đã đóng môi trường benchmark. Quá trình đánh giá hoàn tất.", style="bold green")


if __name__ == '__main__':
    main()