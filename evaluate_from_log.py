import click
import re
import json
from rich.console import Console
from openai import OpenAI
import instructor
import os
from autopenbench.utils import load_data, load_milestones
from autopenbench.driver import PentestDriver
from autopenbench.evaluation import Evaluator
from autopenbench.tools import ExecuteBash, FinalAnswer, SSHConnect
from dotenv import load_dotenv

# Tải API key từ file .env
load_dotenv()
OPENAI_KEY = os.getenv('OPENAI_KEY')

OBSERVATION_CHAR_LIMIT = 15000

def parse_log_file(log_path: str):
    """
    Hàm này đọc và phân tích file log chi tiết do VulnBot tạo ra,
    và tự động thêm bước "submit" nếu tìm thấy cờ.
    """
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file log tại '{log_path}'")
        return None

    # Bước 1: Trích xuất các cặp Action/Observation như bình thường
    pattern = re.compile(
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \| INFO\s+\| roles\.role:_react:\d+ - Action:(.*?)\nObservation:(.*?)(?=\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} \||\Z)",
        re.DOTALL
    )
    matches = pattern.findall(content)
    
    steps = []
    for command, output in matches:
        cleaned_output = output.strip()
        if not cleaned_output:
             cleaned_output = "[EMPTY OBSERVATION]"
        steps.append({
            "command": command.strip(),
            "output": cleaned_output
        })

    # Bước 2: Tìm kiếm bằng chứng tìm thấy cờ trong toàn bộ log
    flag_finder_pattern = re.compile(r'LLM flag finder response:.*?{"flag_found":\s*true,\s*"extracted_flag":\s*"(.*?)"}')
    flag_match = flag_finder_pattern.search(content)
    
    if flag_match:
        extracted_flag = flag_match.group(1)
        print(f"[THÔNG TIN] Đã tự động phát hiện cờ trong log: {extracted_flag}")
        # Thêm một bước "submit" nhân tạo vào cuối danh sách
        steps.append({
            "command": f"submit {extracted_flag}",
            "output": "Flag automatically submitted by evaluator based on logs."
        })

    return steps

def command_to_action(command_str: str, kali_ip: str):
    command_lower = command_str.lower()
    
    if command_lower.startswith("submit"):
        # Phân tích cờ, có thể có dấu ngoặc kép hoặc không
        try:
            flag = command_str.split(" ", 1)[1].strip().strip('"').strip("'")
            return FinalAnswer(flag=flag)
        except IndexError:
             return FinalAnswer(flag="") 
    
    if command_lower.startswith("ssh"):
        try:
            parts = command_str.split()
            user_host = parts[1]
            user, host = user_host.split('@')
            password = parts[3] if len(parts) > 3 and parts[2] == '-p' else ""
            return SSHConnect(machine_ipaddr=host, user=user, psw=password)
        except:
            pass

    return ExecuteBash(machine_ipaddr=kali_ip, cmd=command_str)

@click.command()
@click.option('--log-file', help='Đường dẫn đến file log của VulnBot.', required=True)
@click.option('--test-case', help='Tên bài test (ví dụ: web_security).', required=True)
@click.option('--test-index', help='Chỉ số của bài test trong bộ test case.', type=int, required=True)
@click.option('--debug-parse', is_flag=True, help='Chế độ gỡ lỗi: Chỉ phân tích log và thoát.')
def main(log_file, test_case, test_index, debug_parse):
    console = Console()
    console.print(f"Bắt đầu quá trình từ file log: [bold cyan]{log_file}[/bold cyan]", style="bold green")

    
    console.print("\n--- [Bước 1/3] Đang phân tích file log... ---", style="yellow")
    log_steps = parse_log_file(log_file)

    if log_steps is None:
        return
    if not log_steps:
        console.print("[bold red]Lỗi: Không phân tích được hành động nào từ file log.[/bold red]")
        return
        
    console.print(f"Phân tích thành công! Tìm thấy [bold green]{len(log_steps)}[/bold green] bước.")

    if debug_parse:
        console.print("\n--- KẾT QUẢ PHÂN TÍCH LOG (CHẾ ĐỘ GỠ LỖI) ---", style="bold blue")
        console.print(json.dumps(log_steps, indent=2, ensure_ascii=False))
        console.print("\nChế độ gỡ lỗi đã hoàn tất.", style="green")
        return

    console.print("\n--- [Bước 2/3] Đang khởi tạo môi trường benchmark và evaluator... ---", style="yellow")
    try:
        game = load_data('in-vitro')[test_case][test_index]
        driver = PentestDriver(game['task'], game['flag'], game['target'])
        driver.reset()
        
        if not OPENAI_KEY:
            console.print("[bold red]Lỗi: Không tìm thấy OPENAI_KEY. Hãy tạo file .env.[/bold red]")
            return
            
        initial_command_milestones = load_milestones('command', 'in-vitro', test_case, test_index)
        initial_stage_milestones = load_milestones('stage', 'in-vitro', test_case, test_index)
        total_cmd_ms = len(initial_command_milestones)
        total_stg_ms = len(initial_stage_milestones)
        evaluator = Evaluator(OPENAI_KEY, list(initial_command_milestones), list(initial_stage_milestones))
        console.print("Khởi tạo thành công!", style="green")
    except Exception as e:
        console.print(f"[bold red]Lỗi khi khởi tạo: {e}[/bold red]")
        return

    console.print("\n--- [Bước 3/3] Đang tái hiện và đánh giá các bước... ---", style="yellow")
    done = False
    for i, step_data in enumerate(log_steps):
        if done:
            break
        
        console.print(f"\n--- Bước {i+1}/{len(log_steps)} ---", style="bold blue")
        command_from_log = step_data['command']
        console.print(f"Hành động từ Log: [dim]{command_from_log}[/dim]")
        
        kali_ip_for_benchmark = '127.0.0.1'
        action = command_to_action(command_from_log, kali_ip_for_benchmark)
        console.print(f"Hành động đã chuyển đổi: [dim]{action}[/dim]")
        
        observation, done = driver.step(action)
        
        if len(observation) > OBSERVATION_CHAR_LIMIT:
            half_limit = OBSERVATION_CHAR_LIMIT // 2
            truncated_observation = (
                observation[:half_limit]
                + "\n\n...[OUTPUT TRUNCATED]...\n\n"
                + observation[-half_limit:]
            )
            evaluation_input = f"Action: {action}\nObservation: {truncated_observation}"
            console.print("[yellow]Cảnh báo: Output quá dài, đã được cắt bớt trước khi gửi đi đánh giá.[/yellow]")
        else:
            evaluation_input = f"Action: {action}\nObservation: {observation}"
        
        console.print("Đang gọi API để đánh giá bước đi...")
        evaluator.evaluate_step(evaluation_input)
        
    console.print("\n--- KẾT QUẢ ĐÁNH GIÁ CUỐI CÙNG ---", style="bold magenta")
    cmd_score = evaluator.reached_milestones
    completed_cmd_ms = list(set(initial_command_milestones) - set(evaluator.command_milestones))
    completed_stg_ms = list(set(initial_stage_milestones) - set(evaluator.stage_milestones))
    stg_score = len(completed_stg_ms)

    console.print(f"\n[bold green]Hoàn thành Command Milestones: {cmd_score} / {total_cmd_ms}[/bold green]")
    if completed_cmd_ms:
        for ms in completed_cmd_ms: console.print(f"- {ms}")
    else: console.print("- Không có.")

    console.print(f"\n[bold green]Hoàn thành Stage Milestones: {stg_score} / {total_stg_ms}[/bold green]")
    if completed_stg_ms:
        for ms in completed_stg_ms: console.print(f"- {ms.split(',')[0]}")
    else: console.print("- Không có.")
    
    console.print("\nQuá trình đánh giá hoàn tất.", style="bold green")

if __name__ == '__main__':
    main()