import os
from argparse import ArgumentParser, Namespace
import logging
import re

from tarski.io import PDDLReader

from typing import Pattern


DEFAULT_DATA_PATH: str = os.path.join('resources', 'data', 'CVE-PDDL')
DOMAIN_FILE: str = 'domain.pddl'
PROBLEM_FILE: str = 'problem.pddl'

AP_PATTERN: Pattern[str] = re.compile(r'AP\d+')


def process_problem(reader: PDDLReader, path: str, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    problem = reader.read_problem(os.path.join(path, DOMAIN_FILE), os.path.join(path, PROBLEM_FILE))

    with open(os.path.join(output_path, DOMAIN_FILE), 'w') as f:
        f.write(problem.domain.dump())

    with open(os.path.join(output_path, PROBLEM_FILE), 'w') as f:
        f.write(problem.dump())


def process_data(path: str, output_path: str | None):
    if output_path is None:
        output_path = path

    reader = PDDLReader()

    for cve in os.listdir(path):
        for ap in os.listdir(os.path.join(path, cve)):
            if AP_PATTERN.match(ap):
                logging.info(f'Processing files at `{os.path.join(path, cve, ap)}`')
                process_problem(reader, os.path.join(path, cve, ap), os.path.join(output_path, cve, ap))


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description='Command line tool to preprocess PDDL files')

    parser.add_argument(
        '--data_path',
        type=str,
        default=DEFAULT_DATA_PATH,
        help='Path to the directory with the PDDL files'
    )
    parser.add_argument(
        '--output_path',
        type=str,
        default=None,
        help='Path to the output directory (if not provided files will be overwritten)'
    )

    return parser.parse_args()


def main():
    # Log start
    logging.debug('Script started')

    # Parse arguments
    args: Namespace = parse_arguments()
    logging.debug('Arguments parsed')

    # Run data preprocessing
    process_data(args.data_path, args.output_path)

    # Log end
    logging.debug('Script completed')

    return 0


if __name__ == '__main__':
    main()
