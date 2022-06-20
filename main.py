import argparse
import copy
import time

import logsight.exceptions
from logsight.compare import LogsightCompare
from logsight.authentication import LogsightAuthentication

from logsight.config import set_host

SECONDS_SLEEP = 15

# Instantiate the parser
parser = argparse.ArgumentParser(description='Logsight Init')
parser.add_argument('--username', type=str, help='URL of logsight')
parser.add_argument('--password', type=str, help='Basic auth username')
parser.add_argument('--host', type=str, help='Host name')
parser.add_argument('--baseline_namespace', type=str, help='Baseline namespace')
parser.add_argument('--baseline_container', type=str, help='Baseline container name')
parser.add_argument('--baseline_container_image', type=str, help='Baseline container image')
parser.add_argument('--candidate_namespace', type=str, help='Candidate namespace')
parser.add_argument('--candidate_container', type=str, help='Candidate container')
parser.add_argument('--candidate_image', type=str, help='Candidate image')
parser.add_argument('--risk_threshold', type=int, help='Risk threshold (between 0 and 100)')
args = parser.parse_args()
set_host(args.host)
EMAIL = args.username
PASSWORD = args.password

BASELINE_TAGS = {"namespace": args.baseline_namespace, "container": args.baseline_container, "image": args.baseline_image}
CANDIDATE_TAGS = {"namespace": args.candidate_namespace, "container": args.candidate_container, "image": args.candidate_image}
RISK_THRESHOLD = args.risk_threshold
auth = LogsightAuthentication(email=EMAIL, password=PASSWORD)
time.sleep(SECONDS_SLEEP)
compare = LogsightCompare(auth.token)
flag = 0
n_runs = 5
for (i in range(n_runs)):
    try:
        r = compare.compare(baseline_tags=BASELINE_TAGS,
                            candidate_tags=CANDIDATE_TAGS)
        break
    except Exception as e:
        time.sleep(SECONDS_SLEEP)
       	print("Something went wrong, trying again: ", i)
		if(i == (n_runs-1)):
			exit(0)
 
if r['risk'] >= RISK_THRESHOLD:
    exit(1)
else:
    exit(0)
