import json
from shlex import shlex
from typing import Any

from redis import exceptions

from .pagesession import PageSession
from .redis import NameSpacedRedis

max_batch_size = 20
max_arguments = 25
max_argument_size = 256
escapes = {'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'a': '\a'}
unescapes = {v: k for k, v in escapes.items()}

def reply(value: Any, error: bool) -> dict:
    return {
        'value': value,
        'error': error,
    }


def deny(message: str) -> dict:
    return reply(f'{message} allowed on the interwebz', True)


def snip(value: str, init: int = 0) -> str:
    signature = '... (full value snipped by the interwebz)'
    return value[:max_argument_size - init - len(signature)] + signature


def unescape_argument(argument: str) -> str:
    if len(argument) < 2 or not (argument.startswith('"') or argument.startswith("'")):
        return argument
    value, reply = argument[1:-1], ''
    if argument.startswith('"'):
        result = []
        i = 0
        while i < len(value):
            if value[i] == '\\':
                if i + 1 >= len(value):
                    return value
                if value[i + 1] == 'x' and i + 3 < len(value):
                    try:
                        hex_val = int(value[i+2:i+4], 16)
                        result.append(chr(hex_val))
                        i += 4
                        continue
                    except ValueError:
                        result.append(value[i])
                        i += 1
                        continue
                result.append(escapes.get(value[i + 1], value[i + 1]))
                i += 2
            else:
                result.append(value[i])
                i += 1
        reply = ''.join(result)
    else:
        reply = value.replace("\\'", "'")
    return reply

def escape_strings(resp: Any) -> Any:
    if type(resp) is str:
        escaped = ''
        for c in resp:
            if c == '\\':
                escaped += '\\\\'
            elif c == '"':
                escaped += '\\"'
            elif not c.isprintable():
                escaped += f'\\x{ord(c):02x}'
            else:
                escaped += unescapes.get(c, c)
        if escaped != resp:
            escaped = f'"{escaped}"'
        return escaped
    if type(resp) is list:
        return [escape_strings(x) for x in resp]
    if type(resp) is dict:
        return {k: escape_strings(v) for k, v in resp.items()}
    return resp

def sanitize_exceptions(argv: list) -> Any:
    # TODO: potential "attack" vectors: append, bitfield, sadd, zadd, xadd, hset, lpush/lmove*, sunionstore, zunionstore, ...
    cmd_name = argv[0].lower()
    argc = len(argv)
    if cmd_name == 'setbit' and argc == 4:
        try:
            offset = int(argv[2])
            max_offset = max_argument_size * 8
            if offset > max_offset:
                return f'offset too big - only up to {max_offset} bits allowed'
        except ValueError:
            pass  # Let the Redis server return a proper parsing error :)
    elif cmd_name == 'setrange' and argc == 4:
        try:
            offset = int(argv[2])
            if offset > max_argument_size:
                return f'offset too big - only up to {max_argument_size} bytes allowed'
            argv[3] = argv[3][:(max_argument_size - offset + 1)]
        except ValueError:
            argv[3] = ''
    elif cmd_name in ['quit', 'hello', 'reset', 'auth']:
        return f'the \'{argv[0]}\' command is not'

    return None


def verify_commands(commands: Any) -> Any:
    if type(commands) is not list:
        return 'It posts commands as a list', 400
    if len(commands) > max_batch_size:
        return deny(f'batch is too large. Only up to {max_batch_size} commands')
    return None


def execute_commands(client: NameSpacedRedis, session: PageSession, commands: list) -> list:
    rep = []
    for command in commands:
        try:
            lex = shlex(command, posix=True)
            lex.whitespace_split = True
            lex.commenters = ''
            argv = list(iter(shlex(command, True).get_token, ''))
        except ValueError as e:
            rep.append(reply(str(e), True))
            continue

        argc = len(argv)
        if argc == 0:
            continue
        if argc > max_arguments:
            rep.append(
                deny(f'too many arguments - only up to {max_arguments}'))
            continue

        stronly = True
        for i in range(argc):
            stronly = type(argv[i]) is str
            if not stronly:
                break
            argv[i] = unescape_argument(argv[i])
            if len(argv[i]) > max_argument_size:
                argv[i] = snip(argv[i])
        if not stronly:
            rep.append(deny(f'only string arguments are allowed'))
            continue

        error = sanitize_exceptions(argv)
        if error is not None:
            rep.append(deny(error))
            continue

        try:
            resp = client.execute_namespaced(session, argv)
            if not (argv[0].lower() == 'info' or (argc > 1 and argv[0].lower() == 'client' and argv[1].lower() == 'info')):
                resp = escape_strings(resp)
            rep.append(reply(resp, False))
        except Exception as e:
            rep.append(reply(str(e), True))

    return rep
