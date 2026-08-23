# TaskPilotSignal

Telegram, Notion, NotebookLM 또는 로컬 문서로 받는 Windows AI 브리핑 자동화

- [홈페이지](https://taskpilotsignal.github.io/TaskPilotSignalPages/)
- [개인정보처리방침](https://taskpilotsignal.github.io/TaskPilotSignalPages/privacy/)
- [EULA](https://taskpilotsignal.github.io/TaskPilotSignalPages/eula/)
- [고객지원](https://taskpilotsignal.github.io/TaskPilotSignalPages/support/)

## Provider 모델 카탈로그 자동화

TaskPilotSignal 1.2.0.0은 이 Pages 저장소의 서명된 모델 카탈로그를 새로 받아서 사용한다. 새 Codex, Claude, Antigravity 모델을 게시할 때 MSIX나 Store 버전을 변경하지 않는다.

- Codex는 로그인된 `codex app-server`의 `model/list` 결과를 사용한다.
- Antigravity는 로그인된 `agy models` 결과와 실제 CLI 모델 ID를 함께 사용한다.
- Claude는 Anthropic이 관리하는 공개 `anthropics/skills` 현재 모델 표만 사용하며, 제한 사용자 전용으로 표시된 모델은 제외한다.
- 새로 관측된 모델만 추가한다. 일시적으로 목록에서 사라진 기존 모델은 자동 삭제하거나 사용 중지하지 않는다.
- 모델 변화가 없어도 만료 45일 전에는 새 sequence와 150일 유효기간으로 다시 서명한다.
- 운영 개인키와 provider 로그인 파일은 내보내거나 저장소, VM, 로그로 복사하지 않는다. 서명은 현재 Windows 사용자의 내보내기 불가 키 저장소에서만 수행한다.

Windows 예약 게시자는 로그인 5분 후와 매일 06:35에 백그라운드로 실행된다. Git 자격 증명 관리자가 Pages 원격 저장소에 push할 수 있어야 하며, Codex와 Antigravity CLI 로그인은 이 Windows 사용자에게 유지되어야 한다.

```powershell
# 변경 예상과 서명 후보만 생성; Pages나 Git을 변경하지 않음
pwsh -NoProfile -File scripts/publish-provider-model-catalog.ps1 -Mode Preview

# 현재 사용자 예약 작업 설치
pwsh -NoProfile -File scripts/publish-provider-model-catalog.ps1 -Mode InstallSchedule

# 결정론적 오프라인 검증
pwsh -NoProfile -File scripts/test-provider-model-catalog-publisher.ps1
```

후보, 실행 결과, 실패 코드는 `D:\Projects\TaskPilotSignal\BuildArtifacts\1.2.0.0\provider_catalog_automation` 아래에만 기록한다. Provider stderr, OAuth 정보, 키 컨테이너 정보는 기록하지 않는다.

GitHub Actions는 매일 공개 파일의 고정 공개키 서명과 남은 유효기간을 독립적으로 확인한다. 실패하면 동일 제목의 GitHub Issue를 열거나 갱신하고, 복구되면 닫는다. `CERT_RENEWAL_REQUIRED`는 현재 고정 공개키를 유지한 인증서 운영 갱신이 필요하다는 뜻이며 앱 버전 변경을 뜻하지 않는다.
