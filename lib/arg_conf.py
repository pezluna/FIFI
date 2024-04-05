import argparse

def init_arg():
    parser = argparse.ArgumentParser(description="Packet Classification")
    
    parser.add_argument(
        "-a", "--algorithm",
        type=str,
        required=False,
        default="c",
        action="store",
        help="Algorithm to use. (l)stm, (g)ru, (c)nn"
    )
    parser.add_argument(
        "-r", "--reset",
        required=False,
        default=False,
        action="store_true",
        help="Reset all data and start from scratch."
    )

    return parser.parse_args()