#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import common
from src.utils import settings
from src.core.injections.controller import checks
from src.core.injections.controller import handler

"""
The "time-based" injection technique on Blind OS Command Injection.
"""

"""
The "time-based" injection technique handler.
"""
def tb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):
    return handler.do_time_relative_proccess(
        url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path
    )

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique):
    # Check if attack is based on time delays.
    if not settings.TIME_RELATIVE_ATTACK:
        checks.time_relative_attaks_msg()
        settings.TIME_RELATIVE_ATTACK = True

    if url_time_response >= settings.SLOW_TARGET_RESPONSE:
        warn_msg = (
            "It is highly recommended, due to serious response delays, "
            "to skip the time-based (blind) technique and to continue "
            "with the file-based (semiblind) technique."
        )
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        go_back = False
        while True:
            if go_back:
                return False
            message = "How do you want to proceed? [(C)ontinue/(s)kip] > "
            proceed_option = common.read_input(message, default="C", check_batch=True)
            if proceed_option.lower() in settings.CHOICE_PROCEED:
                if proceed_option.lower() == "c":
                    tmp_path = ""  # Initialize tmp_path if necessary
                    if tb_injection_handler(
                        url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path
                    ) is False:
                        return False
                elif proceed_option.lower() == "s":
                    from src.core.injections.semiblind.techniques.file_based import fb_handler
                    fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique)
                elif proceed_option.lower() == "q":
                    raise SystemExit()
            else:
                common.invalid_option(proceed_option)
                pass
    else:
        # Fix the missing tmp_path initialization and usage
        tmp_path = ""  # Adjust if another initialization is required
        if tb_injection_handler(
            url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path
        ) is False:
            settings.TIME_RELATIVE_ATTACK = False
            return False
