import subprocess
import sys
import os
from datetime import datetime

INPUT = "UGR16_preprocessed/production_train/train.csv"
OUTPUT_DIR = "UGR16_preprocessed/production_train"
MODEL_PREFIX = "models/ugr16_if"
PYTHON_PATH = "/usr/bin/python3"

CONTAMINATION = "0.01"
N_ESTIMATORS = "800"
MAX_SAMPLES = "262144"
N_JOBS = "-1"
PROGRESS_STEP = "50"
CHUNKSIZE = "100000"
USE_STREAM_FIT = True
SKIP_PREPROCESS = True
MAX_ROWS = None
CREATE_LOG = True
RUN_IN_BACKGROUND = True
TUNE_THRESHOLD = True
TUNE_METRIC = "f1"  # options: 'f1' or 'precxrec'

def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    MODEL_OUTPUT = f"{MODEL_PREFIX}_{timestamp}.joblib"
    
    os.makedirs("logs", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    
    LOG_FILE = f"logs/train_{timestamp}.log" if CREATE_LOG else None
    
    cmd = [PYTHON_PATH, "-u", "model_script.py"]
    cmd.extend(["--input", INPUT])
    cmd.extend(["--output", OUTPUT_DIR])
    cmd.extend(["--model-output", MODEL_OUTPUT])
    cmd.extend(["--contamination", CONTAMINATION])
    cmd.extend(["--n-estimators", N_ESTIMATORS])
    cmd.extend(["--max-samples", MAX_SAMPLES])
    cmd.extend(["--n-jobs", N_JOBS])
    cmd.extend(["--chunksize", CHUNKSIZE])
    
    if USE_STREAM_FIT:
        cmd.append("--stream-fit")
    
    if SKIP_PREPROCESS:
        cmd.append("--skip-preprocess")
    
    if MAX_ROWS is not None:
        cmd.extend(["--max-rows", str(MAX_ROWS)])
    
    if PROGRESS_STEP is not None:
        cmd.extend(["--progress-step", str(PROGRESS_STEP)])

    # Pass through threshold tuning flags for evaluation if desired
    if TUNE_THRESHOLD:
        cmd.append("--tune-threshold")
        cmd.extend(["--tune-metric", str(TUNE_METRIC)])
    
    print("=" * 80)
    print("MODEL TRAINING")
    print("=" * 80)
    print(f"Model: {MODEL_OUTPUT}")
    print(f"Contamination: {CONTAMINATION}")
    print(f"N Estimators: {N_ESTIMATORS}")
    print(f"Max Samples: {MAX_SAMPLES}")
    if LOG_FILE:
        print(f"Log: {LOG_FILE}")
    print("=" * 80)
    
    if RUN_IN_BACKGROUND:
        if LOG_FILE:
            with open(LOG_FILE, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True
                )
            print(f"Started in background. PID: {process.pid}")
            print(f"Monitor: tail -f {LOG_FILE}")
        else:
            print("ERROR: Background mode requires CREATE_LOG=True")
            sys.exit(1)
    else:
        if LOG_FILE:
            with open(LOG_FILE, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )
                
                for line in process.stdout:
                    print(line, end='')
                    log.write(line)
                    log.flush()
                
                process.wait()
                result_code = process.returncode
        else:
            result = subprocess.run(cmd)
            result_code = result.returncode
        
        if result_code == 0:
            print("\nTRAINING COMPLETED")
            print(f"Model: {MODEL_OUTPUT}")
            if LOG_FILE:
                print(f"Log: {LOG_FILE}")
        else:
            print(f"\nTRAINING FAILED (exit code: {result_code})")
            if LOG_FILE:
                print(f"Check log: {LOG_FILE}")
        
        sys.exit(result_code)

if __name__ == "__main__":
    main()
