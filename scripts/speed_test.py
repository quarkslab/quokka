import re
import subprocess
from pathlib import Path


def run_one(path: Path):
    result = subprocess.run(
        args=['idat64', '-OQuokkaAuto:true',
              '-OQuokkaFile:/tmp/out.Quokka',
              '-A', str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    if result.returncode != 0:
        print(f'ERROR FOR BINARY {path}')
        return -1

    for line in result.stderr.splitlines():
        decoded = line.decode('utf-8')
        if 'finished' in decoded:
            match = re.match(r'.*took ([0-9]+)\.[0-9]+', decoded)
            if match:
                return int(match.groups()[0])


def main():
    results = {}
    path = Path('/home/alexis/Project/BinaryInterface/export_files/ida/')
    for idb in path.glob('*.i64'):
        results[idb] = run_one(idb)
        print(f"{idb.name}: {results[idb]}")

    return results


if __name__ == '__main__':
    main()