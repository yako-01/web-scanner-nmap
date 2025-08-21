import os

script_path_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_zap.sh')
print(f"script path __file__ is: {script_path_file}")
script_path_os = os.path.join(os.getcwd(), 'scan_zap.sh')
print(f"script path os is: {script_path_file}")
