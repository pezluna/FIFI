import argparse
from lib.arg_conf import init_arg

import logging
from lib.log_conf import init_logger

from lib.session_data import Sessions
from lib.model import Model

if __name__ == "__main__":
    # Initialize logger and argument parser
    init_logger()

    logger = logging.getLogger("logger")
    args = init_arg()

    sessions = Sessions()

    if args.reset:
        logger.debug("Resetting session data...")
        sessions.reset()
        logger.debug("Session data reset complete.")
    logger.debug("Session data loaded successfully.")
    logger.debug(f"Number of sessions: {len(sessions.sessions)}")
    logger.debug(f"Session IDs: {list(sessions.sessions.keys())}")

    # Initialize model
    model = Model()
    logger.debug("Model initialized successfully.")

    # Train and test model
    result = model.run(sessions, args.algorithm)

    # Visualize results
    model.visualize(result)
    logger.debug("Results visualized successfully.")