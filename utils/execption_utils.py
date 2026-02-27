def extract_execption_string(error_detail:str) ->tuple[str, str]:
    error_parts = error_detail.split('\'')
    message = error_parts[1]
    code = error_parts[3]
    return message, code