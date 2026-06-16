"""Cliente de Claude. Recibe mensajes YA sanitizados y llama a la Messages API.

Privacidad:
- La API de Anthropic NO entrena con datos enviados por API (retención estándar;
  retención cero disponible bajo petición a Anthropic). Aun así, este proxy solo
  envía texto anonimizado.
- No se envía `metadata.user_id` ni ningún identificador del cliente/host/pentester.
- No se añade telemetría propia.
"""

from __future__ import annotations

from typing import Any

import anthropic

from .config import Settings


class ClaudeClient:
    def __init__(self, settings: Settings):
        self._client = anthropic.Anthropic(
            api_key=settings.anthropic_api_key,
            base_url=settings.anthropic_base_url,
        )
        self.default_model = settings.anthropic_model

    @staticmethod
    def split_messages(messages: list[dict]) -> tuple[str | None, list[dict]]:
        """Separa los mensajes 'system' del resto (formato Anthropic)."""
        system_parts: list[str] = []
        convo: list[dict] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            if isinstance(content, list):  # bloques OpenAI -> texto plano
                content = "".join(
                    part.get("text", "") for part in content if isinstance(part, dict)
                )
            if role == "system":
                system_parts.append(content)
            elif role in ("user", "assistant"):
                convo.append({"role": role, "content": content})
        system = "\n\n".join(p for p in system_parts if p) or None
        return system, convo

    def chat(self, *, messages: list[dict], model: str | None = None,
             max_tokens: int = 2000, temperature: float | None = None) -> dict[str, Any]:
        system, convo = self.split_messages(messages)
        if not convo:
            convo = [{"role": "user", "content": ""}]

        kwargs: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "messages": convo,
        }
        if system:
            kwargs["system"] = system
        # Modelos sonnet-4-6 / opus-4-x ignoran temperature en modo adaptive;
        # solo la pasamos si el caller la pidió y el modelo la acepta.
        if temperature is not None and "opus-4-8" not in kwargs["model"] \
                and "opus-4-7" not in kwargs["model"]:
            kwargs["temperature"] = temperature

        response = self._client.messages.create(**kwargs)

        text = "".join(block.text for block in response.content if block.type == "text")
        return {
            "id": response.id,
            "model": response.model,
            "text": text,
            "usage": {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
            "stop_reason": response.stop_reason,
        }

    def run_turn(self, *, system: str | None, messages: list[dict],
                 tools: list[dict] | None = None, model: str | None = None,
                 max_tokens: int = 4000) -> dict:
        """Un turno del loop agéntico (con soporte de tool_use).

        Devuelve un dict con bloques de contenido en formato plano, para que el
        orquestador mantenga el historial sin depender de objetos del SDK.
        """
        kwargs: dict = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools

        response = self._client.messages.create(**kwargs)

        content: list[dict] = []
        for block in response.content:
            if block.type == "text":
                content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                content.append({"type": "tool_use", "id": block.id,
                                "name": block.name, "input": block.input})
        return {
            "content": content,
            "stop_reason": response.stop_reason,
            "usage": {"input_tokens": response.usage.input_tokens,
                      "output_tokens": response.usage.output_tokens},
        }
