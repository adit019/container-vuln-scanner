import sys
from pathlib import Path
from scanner.dockerfile_parser import check as check_dockerfile
if __name__=='__main__':
    sys.exit(check_dockerfile(Path('Dockerfile')))
