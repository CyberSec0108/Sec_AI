"""IMP-040 product feature states shared by the UI and API."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FeatureState(StrEnum):
    LIVE = "LIVE"
    PREVIEW = "PREVIEW"
    BLOCKED = "BLOCKED"
    HIDDEN = "HIDDEN"


@dataclass(frozen=True, slots=True)
class ProductFeature:
    feature_id: str
    title: str
    description: str
    state: FeatureState
    state_label: str
    href: str | None
    availability: str

    def public_view(self) -> dict[str, str | None]:
        return {
            "id": self.feature_id,
            "title": self.title,
            "description": self.description,
            "state": self.state.value,
            "state_label": self.state_label,
            "href": self.href,
            "availability": self.availability,
        }


# [카드수정] 제목·설명·상태·이동 경로를 수정하면 개발 API가 자동 재시작됩니다.
_FEATURES = (
    ProductFeature(
        feature_id="login_security",
        title="로그인",
        description="내 계정의 로그인 상태와 보안 설정을 확인합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/auth/session",
        availability="계정·비밀번호·인증 수단 관리",
    ),
    ProductFeature(
        feature_id="pc_scan",
        title="Windows PC 점검",
        description="Windows OS PC의 보안 설정을 점검합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href=None,
        availability="Windows 실행 파일 연결 후 시작",
    ),
    ProductFeature(
        feature_id="linux_server_scan",
        title="리눅스 서버 점검",
        description="리눅스 서버의 보안 설정을 점검합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/linux-scan",
        availability="Ubuntu·Debian·Rocky·RHEL·AlmaLinux 서버 점검",
    ),
    ProductFeature(
        feature_id="network_switch_scan",
        title="네트워크 스위치 점검",
        description="네트워크 장비(스위치)의 보안 설정을 점검합니다.",
        state=FeatureState.LIVE,
        state_label="개발용",
        href="/ui/switch-scan",
        availability="Aruba AOS-CX 10.13 REST 읽기 전용 N-01~N-38",
    ),
    ProductFeature(
        feature_id="results",
        title="점검 결과",
        description="실제로 수집된 자료와 안전한 확인·조치 방법을 중요도순으로 봅니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/result-center",
        availability="Windows·Linux·스위치 장비별 결과 확인",
    ),
    ProductFeature(
        feature_id="administrator_scan",
        title="관리자 추가 점검",
        description="관리자 권한이 꼭 필요한 다섯 항목만 별도 동의 후 확인합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/results#administrator-scan",
        availability="일반 점검 뒤 선택·동의하여 실행",
    ),
    ProductFeature(
        feature_id="queue_recovery",
        title="작업 복구 상태",
        description="작업이 중간에 멈춰도 다시 이어지고 결과가 중복되지 않는지 봅니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/queue-recovery",
        availability="최근 격리 복구시험 결과",
    ),
    ProductFeature(
        feature_id="storage_recovery",
        title="저장소 복구 상태",
        description="자료 저장소가 멈춘 뒤 원본과 결과 관계를 다시 확인했는지 봅니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/storage-recovery",
        availability="최근 합성자료 복구훈련 결과",
    ),
    ProductFeature(
        feature_id="guide_chat",
        title="가이드 질의",
        description="공식 가이드 기반 보안관련 질의응답 기능입니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/guide-chat",
        availability="주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드",
    ),
    ProductFeature(
        feature_id="model_runtime",
        title="AI 연결 상태",
        description="현재 사용할 모델과 로컬 vLLM 전환 준비 상태를 확인합니다.",
        state=FeatureState.LIVE,
        state_label="연결 확인 가능",
        href="/ui/model-runtime",
        availability="OpenRouter 원격 연결 · 로컬 vLLM 전환 준비 상태",
    ),
    ProductFeature(
        feature_id="known_vulnerability_check",
        title="알려진 취약점 점검",
        description="내 Windows 버전과 공개된 보안 문제를 비교합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/vulnerability-check",
        availability="Windows 우선 지원 · 저장 자료로 오프라인 확인",
    ),
    ProductFeature(
        feature_id="help",
        title="도움말",
        description="점검 시작 방법과 상태 용어를 안내합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/ui/help",
        availability="점검 순서와 용어 안내",
    ),
    ProductFeature(
        feature_id="criteria_defaults",
        title="조직 기본 기준",
        description="점검 전에 적용할 조직 기본값을 버전별로 관리합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/admin/criteria",
        availability="관리자 전용 기준 설정",
    ),
    ProductFeature(
        feature_id="linux_asset_management",
        title="Linux 서버 관리",
        description="점검 서버를 등록하고 SSH 공개키와 연결 상태를 관리합니다.",
        state=FeatureState.LIVE,
        state_label="",
        href="/admin/linux-servers",
        availability="관리자 전용 등록 · 자동 플랫폼 확인",
    ),
    ProductFeature(
        feature_id="audit_pack_draft_assist",
        title="점검 기준 작성 보조",
        description="내부 승인 담당자 전용 DRAFT 작성 기능입니다.",
        state=FeatureState.HIDDEN,
        state_label="내부 전용",
        href=None,
        availability="별도 역할 확인 전 숨김",
    ),
)

_HOME_FEATURE_IDS = frozenset(
    {
        "pc_scan",
        "linux_server_scan",
        "network_switch_scan",
        "guide_chat",
        "known_vulnerability_check",
        "help",
    }
)

_ADMINISTRATOR_FEATURE_IDS = frozenset(
    {
        "results",
        "administrator_scan",
        "queue_recovery",
        "storage_recovery",
        "model_runtime",
        "criteria_defaults",
        "linux_asset_management",
    }
)


def public_feature_registry() -> dict[str, ProductFeature]:
    """Return only features visible to an unauthenticated local user."""

    return {
        feature.feature_id: feature
        for feature in _FEATURES
        if feature.state is not FeatureState.HIDDEN
    }


def home_feature_registry() -> dict[str, ProductFeature]:
    """Return the concise task cards shown to general users."""

    return {
        feature.feature_id: feature
        for feature in _FEATURES
        if feature.feature_id in _HOME_FEATURE_IDS
    }


def administrator_feature_registry() -> dict[str, ProductFeature]:
    """Return operational cards shown only inside the administrator surface."""

    return {
        feature.feature_id: feature
        for feature in _FEATURES
        if feature.feature_id in _ADMINISTRATOR_FEATURE_IDS
    }
