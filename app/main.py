"""نقطه شروع: پنل وب + سرور RADIUS + جمع‌آوری NetFlow + کارهای زمان‌بندی‌شده."""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

import uvicorn

from . import config
from .db import init_db


def setup_logging():
    handlers = []
    if sys.stderr is not None and os.environ.get("NO_CONSOLE_LOG") != "1":
        handlers.append(logging.StreamHandler())
    if config.LOG_FILE:
        handlers.append(RotatingFileHandler(config.LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"))
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def main():
    setup_logging()
    log = logging.getLogger("main")
    log.info("starting: web port %s, RADIUS %s/%s, NetFlow %s, data %s", os.environ.get("WEB_PORT", "8080"),
             config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT, config.NETFLOW_PORT, config.DATA_DIR)
    init_db()
    if config.ENABLE_RADIUS:
        from . import radius_server
        radius_server.start()
    if config.ENABLE_NETFLOW:
        from .netflow import collector
        collector.start()
    if config.ENABLE_SCHEDULER:
        from . import jobs
        jobs.start()
    uvicorn.run("app.web:app", host=os.environ.get("WEB_HOST", "0.0.0.0"), port=int(os.environ.get("WEB_PORT", "8080")),
                proxy_headers=True, log_level="warning", log_config=None)


if __name__ == "__main__":
    main()
