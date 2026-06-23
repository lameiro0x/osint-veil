"""Tests del puente OpenAI↔Anthropic (function calling con privacidad)."""

import json

from proxy.openai_bridge import (
    anthropic_to_oai_message,
    append_glossary,
    oai_messages_to_anthropic,
    oai_tool_choice_to_anthropic,
    oai_tools_to_anthropic,
)


def test_tools_traducidas_a_anthropic():
    tools = [{"type": "function", "function": {
        "name": "subdomain_enum", "description": "Enumera subdominios",
        "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}}}}]
    out = oai_tools_to_anthropic(tools)
    assert out == [{
        "name": "subdomain_enum", "description": "Enumera subdominios",
        "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}}}]


def test_tool_choice_mapping():
    assert oai_tool_choice_to_anthropic("auto") is None
    assert oai_tool_choice_to_anthropic("none") is None
    assert oai_tool_choice_to_anthropic("required") == {"type": "any"}
    assert oai_tool_choice_to_anthropic(
        {"type": "function", "function": {"name": "x"}}) == {"type": "tool", "name": "x"}


def test_mensajes_se_sanitizan_incluyendo_tool_results():
    # sanitize fake: marca dónde actuaría (sustituye el dominio por un token).
    def san(t):
        return t.replace("cliente.com", "DOMAIN_001")

    messages = [
        {"role": "system", "content": "Eres analista de cliente.com"},
        {"role": "user", "content": "investiga cliente.com"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": "whois", "arguments": json.dumps({"domain": "cliente.com"})}}]},
        {"role": "tool", "tool_call_id": "call_1", "content": "registrante: admin@cliente.com"},
    ]
    system, convo = oai_messages_to_anthropic(messages, san)

    assert system == "Eres analista de DOMAIN_001"
    # user
    assert convo[0] == {"role": "user", "content": "investiga DOMAIN_001"}
    # assistant tool_use con argumentos tokenizados (objeto, no string)
    tu = convo[1]["content"][0]
    assert tu["type"] == "tool_use" and tu["id"] == "call_1" and tu["name"] == "whois"
    assert tu["input"] == {"domain": "DOMAIN_001"}
    # tool_result agrupado en turno user, sanitizado
    tr = convo[2]["content"][0]
    assert convo[2]["role"] == "user" and tr["type"] == "tool_result"
    assert tr["tool_use_id"] == "call_1"
    assert "cliente.com" not in tr["content"]


def test_tool_results_consecutivos_se_agrupan():
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "a", "function": {"name": "t1", "arguments": "{}"}},
            {"id": "b", "function": {"name": "t2", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "a", "content": "r1"},
        {"role": "tool", "tool_call_id": "b", "content": "r2"},
    ]
    _, convo = oai_messages_to_anthropic(messages, lambda t: t)
    assert convo[1]["role"] == "user"
    ids = [b["tool_use_id"] for b in convo[1]["content"]]
    assert ids == ["a", "b"]  # ambos en un único turno user


def test_respuesta_tool_use_rehidrata_argumentos():
    # rehydrate fake: token -> valor real.
    def rehy(t):
        return t.replace("DOMAIN_001", "cliente.com")

    blocks = [
        {"type": "text", "text": "Voy a enumerar DOMAIN_001"},
        {"type": "tool_use", "id": "call_9", "name": "subfinder",
         "input": {"domain": "DOMAIN_001"}},
    ]
    msg, finish = anthropic_to_oai_message(blocks, rehy, rehydrate_text=False)
    assert finish == "tool_calls"
    # Texto NO rehidratado (política por defecto): sigue con token.
    assert msg["content"] == "Voy a enumerar DOMAIN_001"
    # Argumentos SÍ rehidratados → el cliente ejecuta contra el objetivo real.
    args = json.loads(msg["tool_calls"][0]["function"]["arguments"])
    assert args == {"domain": "cliente.com"}
    assert msg["tool_calls"][0]["id"] == "call_9"


def test_respuesta_texto_final_stop():
    msg, finish = anthropic_to_oai_message(
        [{"type": "text", "text": "Informe final"}], lambda t: t)
    assert finish == "stop"
    assert msg["content"] == "Informe final"
    assert "tool_calls" not in msg


def test_rehidratacion_no_rompe_json_con_valores_raros():
    # Valor real con comillas/barra: _walk rehidrata por-valor y json.dumps escapa.
    def rehy(t):
        return t.replace("PATH_001", 'C:\\a "b"')

    blocks = [{"type": "tool_use", "id": "c", "name": "t",
               "input": {"p": "PATH_001"}}]
    msg, _ = anthropic_to_oai_message(blocks, rehy)
    args = json.loads(msg["tool_calls"][0]["function"]["arguments"])  # no lanza
    assert args == {"p": 'C:\\a "b"'}


def test_glossary_solo_si_ultimo_turno_es_user():
    convo_user = [{"role": "user", "content": "hola"}]
    append_glossary(convo_user, "GLOSARIO")
    assert "GLOSARIO" in convo_user[-1]["content"]

    convo_asst = [{"role": "assistant", "content": [{"type": "tool_use", "id": "x",
                   "name": "t", "input": {}}]}]
    append_glossary(convo_asst, "GLOSARIO")  # no debe tocar (rompería adyacencia)
    assert convo_asst[-1]["role"] == "assistant"
    assert all(b["type"] == "tool_use" for b in convo_asst[-1]["content"])
