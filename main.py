import argparse
import copy
import time

import logsight.exceptions
from logsight.compare import LogsightCompare
from logsight.authentication import LogsightAuthentication

from utils import create_verification_report

from logsight.config import set_host

SECONDS_SLEEP = 15

# Instantiate the parser
parser = argparse.ArgumentParser(description='Logsight Init')
parser.add_argument('--username', type=str, help='URL of logsight')
parser.add_argument('--password', type=str, help='Basic auth username')
parser.add_argument('--host', type=str, help='Host name')
parser.add_argument('--baseline_namespace_name', type=str, help='Baseline namespace name')
parser.add_argument('--baseline_application_name', type=str, help='Baseline application name')
parser.add_argument('--baseline_container_image', type=str, help='Baseline container image')
parser.add_argument('--candidate_namespace_name', type=str, help='Candidate namespace name')
parser.add_argument('--candidate_application_name', type=str, help='Candidate application name')
parser.add_argument('--candidate_container_image', type=str, help='Candidate container image')
parser.add_argument('--risk_threshold', type=int, help='Risk threshold (between 0 and 100)')
set_host(args.host)
args = parser.parse_args()
EMAIL = args.username
PASSWORD = args.password

BASELINE_TAGS = {"namespace_name": args.baseline_namespace_name, "applicationName": args.baseline_application_name, "container_image": args.baseline_container_image}
CANDIDATE_TAGS = {"namespace_name": args.candidate_namespace_name, "applicationName": args.candidate_application_name, "container_image": args.candidate_container_image}
RISK_THRESHOLD = args.risk_threshold
auth = LogsightAuthentication(email=EMAIL, password=PASSWORD)
time.sleep(SECONDS_SLEEP)
compare = LogsightCompare(auth.token)
flag = 0
while True:
    try:
        r = compare.compare(baseline_tags=BASELINE_TAGS,
                            candidate_tags=CANDIDATE_TAGS)
        print(r)
        break
    except logsight.exceptions.Conflict as conflict:
        time.sleep(SECONDS_SLEEP)
        print("Conflict, sleeping..")
    except Exception as e:
        time.sleep(SECONDS_SLEEP)
        if flag == 0:
            BASELINE_TAGS = copy.deepcopy(CANDIDATE_TAGS)
            flag += 1
        elif flag == 1:
            CANDIDATE_TAGS = copy.deepcopy(BASELINE_TAGS)
            flag += 1
        else:
            print("Both tags do not exist! We cant perform verification!")
            exit(0)

report = create_verification_report(vresults=r,
                                    baseline_tags=BASELINE_TAGS,
                                    candidate_tags=CANDIDATE_TAGS)
print(report)

if r['risk'] >= RISK_THRESHOLD:
    exit(0)
else:
    exit(0)
