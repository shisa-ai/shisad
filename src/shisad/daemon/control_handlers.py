"""Service-owned typed control-handler graph."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from shisad.core.api.rpc_registry import RpcHandlerGroup, RpcMethodDescriptor
from shisad.core.interfaces import TypedHandler
from shisad.daemon.handlers import (
    AdminHandlers,
    AssistantHandlers,
    ConfirmationHandlers,
    DashboardHandlers,
    MemoryHandlers,
    PlanHandlers,
    SessionHandlers,
    SkillHandlers,
    TaskHandlers,
    ToolExecutionHandlers,
)
from shisad.daemon.handlers._impl import HandlerImplementation

if TYPE_CHECKING:
    from shisad.daemon.services import DaemonServices


class DaemonControlHandlers:
    """Own the typed handler groups used by control RPCs and live ingress."""

    admin: AdminHandlers
    assistant: AssistantHandlers
    confirmation: ConfirmationHandlers
    dashboard: DashboardHandlers
    memory: MemoryHandlers
    plan_steps: PlanHandlers
    session: SessionHandlers
    skills: SkillHandlers
    tasks: TaskHandlers
    tool_execution: ToolExecutionHandlers

    def __new__(
        cls,
        *,
        services: DaemonServices,
    ) -> DaemonControlHandlers:
        owned = getattr(services, "control_handlers", None)
        if isinstance(owned, cls):
            return owned
        return super().__new__(cls)

    def __init__(self, *, services: DaemonServices) -> None:
        if "_impl" in self.__dict__:
            existing_impl = self.__dict__["_impl"]
            if not isinstance(existing_impl, HandlerImplementation):
                raise RuntimeError("control handler graph has an invalid implementation owner")
            if existing_impl._services is not services:
                raise RuntimeError("control handler graph cannot change service owner")
            return

        impl = HandlerImplementation(services=services)
        self._impl = impl
        internal_ingress_marker = services.internal_ingress_marker
        self.session = SessionHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self.plan_steps = PlanHandlers(impl, internal_ingress_marker=internal_ingress_marker)
        self.tool_execution = ToolExecutionHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.confirmation = ConfirmationHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.memory = MemoryHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.skills = SkillHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.tasks = TaskHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.dashboard = DashboardHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.assistant = AssistantHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )
        self.admin = AdminHandlers(
            impl,
            internal_ingress_marker=internal_ingress_marker,
        )

    def bind_rpc_handler(self, descriptor: RpcMethodDescriptor) -> TypedHandler:
        """Bind one explicit descriptor to this service-owned handler graph."""

        groups: dict[RpcHandlerGroup, object] = {
            RpcHandlerGroup.ADMIN: self.admin,
            RpcHandlerGroup.ASSISTANT: self.assistant,
            RpcHandlerGroup.CONFIRMATION: self.confirmation,
            RpcHandlerGroup.DASHBOARD: self.dashboard,
            RpcHandlerGroup.MEMORY: self.memory,
            RpcHandlerGroup.PLAN_STEPS: self.plan_steps,
            RpcHandlerGroup.SESSION: self.session,
            RpcHandlerGroup.SKILLS: self.skills,
            RpcHandlerGroup.TASKS: self.tasks,
            RpcHandlerGroup.TOOL_EXECUTION: self.tool_execution,
        }
        owner = groups[descriptor.handler_group]
        handler = getattr(owner, descriptor.handler_method, None)
        if not callable(handler):
            raise RuntimeError(
                f"control RPC handler does not resolve: {descriptor.name} "
                f"({descriptor.handler_group.value}.{descriptor.handler_method})"
            )
        return cast(TypedHandler, handler)
