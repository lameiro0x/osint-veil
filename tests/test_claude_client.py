"""Tests del glue OpenAI->Anthropic (sin API real, cliente Anthropic falso)."""

from proxy.claude_client import ClaudeClient
from proxy.config import Settings


class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Usage:
    input_tokens = 10
    output_tokens = 5


class _Resp:
    id = "msg_1"
    model = "claude-test"
    stop_reason = "end_turn"
    usage = _Usage()

    def __init__(self, content):
        self.content = content


class _Messages:
    def __init__(self, resp):
        self._resp = resp
        self.kwargs = None

    def create(self, **kw):
        self.kwargs = kw
        return self._resp


class _FakeAnthropic:
    def __init__(self, resp):
        self.messages = _Messages(resp)


def _client(resp):
    c = ClaudeClient(Settings(anthropic_api_key="x"))
    c._client = _FakeAnthropic(resp)
    return c


def test_split_messages_separa_system():
    system, convo = ClaudeClient.split_messages([
        {"role": "system", "content": "eres analista"},
        {"role": "user", "content": "hola"},
        {"role": "assistant", "content": "qué tal"},
    ])
    assert system == "eres analista"
    assert convo == [{"role": "user", "content": "hola"},
                     {"role": "assistant", "content": "qué tal"}]


def test_split_messages_aplana_bloques():
    system, convo = ClaudeClient.split_messages([
        {"role": "user", "content": [{"type": "text", "text": "a"},
                                     {"type": "text", "text": "b"}]},
    ])
    assert system is None
    assert convo == [{"role": "user", "content": "ab"}]


def test_run_turn_parsea_text_y_tool_use():
    resp = _Resp([_Block(type="text", text="hola"),
                  _Block(type="tool_use", id="t1", name="dns", input={"host": "x"})])
    c = _client(resp)
    out = c.run_turn(system="S", messages=[{"role": "user", "content": "hi"}],
                     tools=[{"name": "dns"}])
    assert out["stop_reason"] == "end_turn"
    assert out["usage"] == {"input_tokens": 10, "output_tokens": 5}
    types = [b["type"] for b in out["content"]]
    assert types == ["text", "tool_use"]
    assert out["content"][1] == {"type": "tool_use", "id": "t1", "name": "dns",
                                 "input": {"host": "x"}}
    # system y tools llegaron a la API.
    assert c._client.messages.kwargs["system"] == "S"
    assert c._client.messages.kwargs["tools"] == [{"name": "dns"}]


def test_chat_devuelve_texto_y_usage():
    resp = _Resp([_Block(type="text", text="respuesta")])
    c = _client(resp)
    out = c.chat(messages=[{"role": "system", "content": "sys"},
                           {"role": "user", "content": "q"}])
    assert out["text"] == "respuesta"
    assert out["usage"]["total_tokens"] == 15
    # system se enrutó al parámetro system, no a messages.
    assert c._client.messages.kwargs["system"] == "sys"
    assert all(m["role"] != "system" for m in c._client.messages.kwargs["messages"])
