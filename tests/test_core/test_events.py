"""Tests for the event bus."""

import pytest

from aegisdroid.core.events import Event, EventBus


@pytest.fixture
def bus():
    return EventBus()


class TestEventBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("test.event", handler)
        await bus.publish(Event(name="test.event", data={"key": "value"}))

        assert len(received) == 1
        assert received[0].data["key"] == "value"

    @pytest.mark.asyncio
    async def test_wildcard_handler(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event.name)

        bus.subscribe("*", handler)
        await bus.publish(Event(name="event.a"))
        await bus.publish(Event(name="event.b"))

        assert len(received) == 2
        assert "event.a" in received
        assert "event.b" in received

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        received = []

        async def handler(event: Event):
            received.append(event)

        bus.subscribe("test", handler)
        await bus.publish(Event(name="test"))
        assert len(received) == 1

        bus.unsubscribe("test", handler)
        await bus.publish(Event(name="test"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_history(self, bus):
        await bus.publish(Event(name="a"))
        await bus.publish(Event(name="b"))
        await bus.publish(Event(name="a"))

        all_events = bus.get_history()
        assert len(all_events) == 3

        a_events = bus.get_history("a")
        assert len(a_events) == 2
