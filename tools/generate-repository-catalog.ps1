[CmdletBinding()]
param(
    [string]$OutputPath = "docs\maintenance\프로젝트_구조_및_파일_기능_카탈로그.md"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ProjectPrefix = $ProjectRoot.TrimEnd("\") + "\"
$ResolvedOutput = [System.IO.Path]::GetFullPath((Join-Path $ProjectRoot $OutputPath))

if (-not $ResolvedOutput.StartsWith($ProjectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath must stay inside the Sec_AI project directory."
}

$ExcludedDirectoryNames = @(
    ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__",
    "build", "dist", "node_modules", "out"
)
$ExcludedRootDirectories = @(".runtime", "runtime", "downloads", "tmp")
$ExcludedRootFiles = @(".env", "명령")

function Get-RelativePath {
    param([Parameter(Mandatory = $true)][string]$FullName)

    return $FullName.Substring($ProjectPrefix.Length).Replace("\", "/")
}

function Test-ExcludedPath {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$File)

    $RelativePath = Get-RelativePath -FullName $File.FullName
    $Segments = $RelativePath -split "/"

    if ($Segments.Count -eq 1 -and $ExcludedRootFiles -contains $Segments[0]) {
        return $true
    }
    if ($Segments.Count -gt 1 -and $ExcludedRootDirectories -contains $Segments[0]) {
        return $true
    }
    foreach ($Segment in $Segments) {
        if ($ExcludedDirectoryNames -contains $Segment) {
            return $true
        }
    }
    return $false
}

function Test-ExcludedDirectory {
    param([Parameter(Mandatory = $true)][System.IO.DirectoryInfo]$Directory)

    if ($ExcludedDirectoryNames -contains $Directory.Name) {
        return $true
    }
    if ($Directory.Parent.FullName -eq $ProjectRoot -and
        $ExcludedRootDirectories -contains $Directory.Name) {
        return $true
    }
    if ($Directory.FullName.StartsWith(
        (Join-Path $ProjectRoot "portable\out"),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        return $true
    }
    return $false
}

function Get-RepositoryFiles {
    $Pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $Pending.Push((Get-Item -LiteralPath $ProjectRoot))
    $Result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    while ($Pending.Count -gt 0) {
        $Current = $Pending.Pop()
        try {
            foreach ($File in Get-ChildItem -LiteralPath $Current.FullName -File -Force -ErrorAction Stop) {
                if (-not (Test-ExcludedPath -File $File)) {
                    $Result.Add($File)
                }
            }
            foreach ($Directory in Get-ChildItem -LiteralPath $Current.FullName -Directory -Force -ErrorAction Stop) {
                if (-not (Test-ExcludedDirectory -Directory $Directory)) {
                    $Pending.Push($Directory)
                }
            }
        } catch [System.UnauthorizedAccessException] {
            Write-Warning "접근 권한이 없어 카탈로그에서 제외했습니다: $($Current.FullName)"
        }
    }
    return $Result
}

function ConvertTo-OneLine {
    param(
        [AllowEmptyString()][string]$Text,
        [int]$MaximumLength = 180
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ""
    }
    $OneLine = ($Text -replace "\s+", " ").Trim().Replace("|", "\|")
    if ($OneLine.Length -le $MaximumLength) {
        return $OneLine
    }
    return $OneLine.Substring(0, $MaximumLength - 1).TrimEnd() + "…"
}

function Get-TextPreview {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$File,
        [int]$MaximumLines = 180
    )

    try {
        return @(Get-Content -LiteralPath $File.FullName -Encoding UTF8 -TotalCount $MaximumLines)
    } catch {
        return @()
    }
}

function Get-MarkdownTitle {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    foreach ($Line in $Lines) {
        if ($Line -match "^#\s+(.+?)\s*$") {
            return ConvertTo-OneLine -Text $Matches[1]
        }
    }
    return ""
}

function Get-PythonSummary {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $FirstCodeIndex = -1
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        $Candidate = $Lines[$Index].Trim()
        if ($Candidate -and -not $Candidate.StartsWith("#!") -and -not $Candidate.StartsWith("# -*-")) {
            $FirstCodeIndex = $Index
            break
        }
    }

    $Description = ""
    $DoubleQuoteDelimiter = [string]::new([char]'"', 3)
    $SingleQuoteDelimiter = [string]::new([char]"'", 3)
    $FirstCode = if ($FirstCodeIndex -ge 0) { $Lines[$FirstCodeIndex].Trim() } else { "" }
    if ($FirstCode.StartsWith($DoubleQuoteDelimiter) -or
        $FirstCode.StartsWith($SingleQuoteDelimiter)) {
        $Delimiter = if ($FirstCode.StartsWith($DoubleQuoteDelimiter)) {
            $DoubleQuoteDelimiter
        } else {
            $SingleQuoteDelimiter
        }
        $Parts = [System.Collections.Generic.List[string]]::new()
        $Remainder = $FirstCode.Substring(3)
        if ($Remainder.Contains($Delimiter)) {
            $Description = $Remainder.Split(@($Delimiter), 2, [System.StringSplitOptions]::None)[0]
        } else {
            if ($Remainder) {
                $Parts.Add($Remainder)
            }
            for ($Index = $FirstCodeIndex + 1; $Index -lt $Lines.Count; $Index++) {
                if ($Lines[$Index].Contains($Delimiter)) {
                    $Parts.Add($Lines[$Index].Split(@($Delimiter), 2, [System.StringSplitOptions]::None)[0])
                    break
                }
                $Parts.Add($Lines[$Index])
            }
            $Description = $Parts -join " "
        }
    }

    $Symbols = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in $Lines) {
        if ($Line -match "^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(" -or
            $Line -match "^class\s+([A-Za-z_][A-Za-z0-9_]*)") {
            if (-not $Symbols.Contains($Matches[1])) {
                $Symbols.Add($Matches[1])
            }
        }
        if ($Symbols.Count -ge 8) {
            break
        }
    }

    return [pscustomobject]@{
        Description = ConvertTo-OneLine -Text $Description
        Details = if ($Symbols.Count -gt 0) { "주요 정의: " + ($Symbols -join ", ") } else { "공개 최상위 정의 없음" }
    }
}

function Get-PowerShellSummary {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $Functions = [System.Collections.Generic.List[string]]::new()
    $Parameters = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in $Lines) {
        if ($Line -match "^\s*function\s+([A-Za-z0-9_-]+)") {
            if (-not $Functions.Contains($Matches[1])) {
                $Functions.Add($Matches[1])
            }
        }
        if ($Line -match '\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|,|\))') {
            $Name = $Matches[1]
            if ($Parameters.Count -lt 8 -and -not $Parameters.Contains($Name)) {
                $Parameters.Add($Name)
            }
        }
    }

    $Parts = [System.Collections.Generic.List[string]]::new()
    if ($Parameters.Count -gt 0) {
        $Parts.Add("입력: " + ($Parameters -join ", "))
    }
    if ($Functions.Count -gt 0) {
        $Parts.Add("함수: " + (($Functions | Select-Object -First 8) -join ", "))
    }
    if ($Parts.Count -eq 0) {
        $Parts.Add("순차 실행 스크립트")
    }
    return $Parts -join "; "
}

function Get-JavaScriptSummary {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $Symbols = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in $Lines) {
        if ($Line -match "(?:^|\s)(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)" -or
            $Line -match "^\s*(?:export\s+)?const\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=") {
            if (-not $Symbols.Contains($Matches[1])) {
                $Symbols.Add($Matches[1])
            }
        }
        if ($Symbols.Count -ge 8) {
            break
        }
    }
    if ($Symbols.Count -eq 0) {
        return "브라우저 초기화·이벤트 처리 코드"
    }
    return "주요 정의: " + ($Symbols -join ", ")
}

function Get-JsonSummary {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $Keys = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in $Lines) {
        if ($Line -match '^\s{0,4}"([^"\\]+)"\s*:') {
            $Key = $Matches[1]
            if (-not $Keys.Contains($Key)) {
                $Keys.Add($Key)
            }
        }
        if ($Keys.Count -ge 8) {
            break
        }
    }
    if ($Keys.Count -eq 0) {
        return "JSON 배열 또는 값 중심 계약"
    }
    return "대표 키: " + ($Keys -join ", ")
}

function Get-FolderDescription {
    param([Parameter(Mandatory = $true)][string]$Directory)

    switch -Regex ($Directory) {
        '^\.$' { return "프로젝트 진입점, 공통 설정과 현재 상태 정본" }
        '^apps/api' { return "FastAPI HTTP·SSE·인증·권한·제품 흐름 Adapter" }
        '^apps/model_gateway' { return "OpenAI 호환 내부 모델 Gateway와 upstream 격리" }
        '^apps/scheduler' { return "Celery Beat 기반 예약 작업 골격" }
        '^apps/web/static' { return "브라우저 JavaScript·CSS·정적 자산" }
        '^apps/web/templates' { return "Jinja2 화면·fragment·component 템플릿" }
        '^apps/web' { return "사용자 Web UI 패키지와 고정 표시 자료" }
        '^apps/worker' { return "Queue 소비·복구·평가 application 실행 진입점" }
        '^apps' { return "실행 가능한 API·Worker·Scheduler·Model Gateway application" }
        '^audit_packs' { return "KISA 기준 DRAFT Pack·Fixture·Adapter Catalog·참조 snapshot" }
        '^collectors' { return "Windows one-shot Collector와 읽기 전용 Probe·제출 계약" }
        '^data(?:/|$)' { return "승인된 가이드 원문 등 비코드 정적 자료" }
        '^database/alembic' { return "append-only 순차 DB migration과 Alembic 설정" }
        '^database/schemas' { return "JSON Schema·유효/무효 예제·계약 검증기" }
        '^database/verification' { return "DB·Schema·결정론 검증 도구" }
        '^database' { return "PostgreSQL migration과 기계 판독 데이터 계약" }
        '^deploy/compose' { return "개발·검증 Docker Compose 서비스 조합" }
        '^deploy/docker' { return "잠긴 기반 이미지를 사용하는 구성요소별 Dockerfile" }
        '^deploy/verification' { return "완료 주장과 시험·공급망을 뒷받침하는 변경 불가 이력 증적" }
        '^deploy' { return "배포·Gateway·잠금·VM 시험·검증 구성" }
        '^docs/adr' { return "승인 상태와 변경 이력을 가진 Architecture Decision Record" }
        '^docs/guides' { return "사용자·운영자·유지보수 담당자 안내" }
        '^docs/maintenance' { return "저장소 구조·파일 역할·정기 유지보수 절차" }
        '^docs/plans' { return "미완료 Gate와 단계별 실행·확장 계획" }
        '^docs' { return "사람이 읽는 설계·계획·운영 문서의 통합 진입점" }
        '^guides' { return "검색 적재용 Guide Catalog·페이지·Control mapping·평가 자료" }
        '^portable' { return "같은 조직의 다른 Windows PC로 옮기는 source/image 묶음 도구" }
        '^requirements/lock' { return "플랫폼별 exact version·hash 의존성 잠금" }
        '^requirements' { return "Python 직접 의존성 입력·잠금·공급망 검증" }
        '^src/security_audit/analysis' { return "검증·정규화·적용성·규칙·Finding의 결정론 Core" }
        '^src/security_audit/application' { return "유스케이스 조정, AI 설명·검색·보고서·제출 흐름" }
        '^src/security_audit/infrastructure' { return "PostgreSQL·Queue·외부 모델·저장소 구현 Adapter" }
        '^src/security_audit/platforms' { return "Windows·Linux·Switch 공통 계약과 플랫폼별 읽기 Adapter" }
        '^src/security_audit' { return "Sec_AI 도메인·application·infrastructure source package" }
        '^src' { return "제품 핵심 Python source" }
        '^tests/browser' { return "실제 브라우저 표시·접근성·보안 회귀" }
        '^tests/contract' { return "Schema·Pack·API 계약 회귀" }
        '^tests/fixtures' { return "비식별 합성 입력과 기대 결과" }
        '^tests/unit' { return "모듈·유스케이스 단위 회귀" }
        '^tests' { return "자동화 시험과 합성 Fixture" }
        '^tools' { return "개발·빌드·검증·이전·운영 보조 명령" }
        default { return "상위 구성요소의 세부 자료와 구현" }
    }
}

function Get-MaintenanceNote {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    switch -Regex ($RelativePath) {
        '^database/alembic/versions/' { return "기존 migration 수정 금지; 변경은 새 migration으로 추가" }
        '^database/schemas/' { return "계약 우선 변경 후 valid·invalid 예제와 validator를 함께 실행" }
        '^audit_packs/' { return "DRAFT를 운영 APPROVED로 승격하지 말고 Fixture·서명·결정론 Gate 유지" }
        '^collectors/' { return "읽기 전용·고정 argv·timeout·출력 상한·설정 diff 0 유지" }
        '^deploy/verification/' { return "감사 이력 보존 대상; 현재 문서와 다르다는 이유로 삭제·덮어쓰기 금지" }
        '^deploy/compose/|^deploy/docker/' { return "인프라 변경은 사용자 승인과 관련 통합시험·재빌드 필요" }
        '^requirements/lock/' { return "수동 편집보다 승인된 resolver로 재생성하고 hash·SBOM 검증" }
        '^requirements/' { return "신규 production 의존성은 승인·잠금·취약점 검토 후 추가" }
        '^apps/web/templates/|^apps/web/static/' { return "CSP·CSRF·XSS·접근성·모바일 회귀를 함께 확인" }
        '^apps/api/' { return "DTO·RBAC·RLS·CSRF·IDOR·안전한 오류 경계 유지" }
        '^src/security_audit/analysis/' { return "공식 판정은 승인 Pack·결정론 규칙만 수행; false PASS 금지" }
        '^src/security_audit/application/.*ai|^apps/model_gateway/' { return "모델 출력은 불신 입력; 공식 상태 불변·민감정보 전송 금지" }
        '^tests/fixtures/' { return "실제 사용자·조직·호스트·secret 대신 비식별 합성값만 사용" }
        '^docs/adr/' { return "결정 의미 변경 시 version·영향 분석·승인 기록과 ADR index hash 갱신" }
        '^docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그\.md$' { return "직접 편집하지 말고 tools/generate-repository-catalog.ps1로 재생성" }
        '^\.env\.example$' { return "변수명·안전한 기본값만 유지하고 실제 secret 값 금지" }
        default { return "관련 시험·문서 링크를 확인하고 요청 범위의 최소 변경만 수행" }
    }
}

function Get-FileAnnotation {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$File)

    $RelativePath = Get-RelativePath -FullName $File.FullName
    $Lines = Get-TextPreview -File $File
    $Extension = $File.Extension.ToLowerInvariant()
    $Stem = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
    $Role = ""
    $Details = ""

    if ($File.Name -eq "README.md") {
        $Title = Get-MarkdownTitle -Lines $Lines
        $Role = if ($Title) { "$Title 안내" } else { "현재 디렉터리 사용 안내" }
        $Details = "구성요소의 목적·실행·제약·검증 경로 설명"
    } elseif ($Extension -eq ".md") {
        $Title = Get-MarkdownTitle -Lines $Lines
        $Role = if ($Title) { $Title } else { "$Stem 문서" }
        $Details = "설계·계획·검증·운영 판단을 사람이 확인하는 Markdown 정본"
    } elseif ($Extension -eq ".py") {
        $Summary = Get-PythonSummary -Lines $Lines
        $Role = if ($Summary.Description) { $Summary.Description } elseif ($File.Name -eq "__init__.py") { "$Stem package 공개 경계" } else { "$Stem Python 모듈" }
        $Details = $Summary.Details
    } elseif ($Extension -eq ".ps1") {
        $Role = "$Stem PowerShell 자동화"
        $Details = Get-PowerShellSummary -Lines $Lines
    } elseif ($Extension -in @(".js", ".cjs")) {
        $Role = "$Stem 브라우저·Node JavaScript"
        $Details = Get-JavaScriptSummary -Lines $Lines
    } elseif ($Extension -eq ".json") {
        if ($RelativePath.StartsWith("database/schemas/")) {
            $Role = "$Stem JSON 데이터 계약·예제"
        } elseif ($RelativePath.StartsWith("tests/fixtures/") -or $RelativePath.Contains("/fixtures/")) {
            $Role = "$Stem 합성 회귀 Fixture"
        } else {
            $Role = "$Stem 구조화 설정·Catalog·Manifest"
        }
        $Details = Get-JsonSummary -Lines $Lines
    } elseif ($Extension -eq ".html") {
        $Role = "$Stem Jinja2 HTML 화면·fragment"
        $Details = "서버 렌더링 구조, 접근성 label과 사용자 동작 진입점"
    } elseif ($Extension -eq ".css") {
        $Role = "$Stem 공통 화면 스타일"
        $Details = "desktop·mobile·theme·상태 표시와 접근성 스타일"
    } elseif ($File.Name -like "*.Dockerfile") {
        $Role = "$Stem container image build 정의"
        $Details = "잠긴 기반 image·최소 Runtime·보안 실행 경계"
    } elseif ($Extension -in @(".yml", ".yaml")) {
        $Role = "$Stem YAML 구성·잠금"
        $Details = "서비스·공급망·환경 조합을 선언하는 기계 판독 설정"
    } elseif ($Extension -in @(".in", ".lock")) {
        $Role = "$Stem Python 의존성 선언·잠금"
        $Details = "직접/전이 의존성 version과 설치 hash 기준"
    } elseif ($File.Name -eq ".env.example") {
        $Role = "다른 PC용 환경 변수 예시"
        $Details = "공개 가능한 변수명·안전한 기본값·secret file 경로"
    } elseif ($File.Name -eq "pyproject.toml") {
        $Role = "Python project·pytest·Ruff·mypy 품질 설정"
        $Details = "package metadata와 표준 검증 도구의 단일 설정"
    } elseif ($File.Name -eq "alembic.ini") {
        $Role = "Alembic migration 실행 설정"
        $Details = "migration script 위치와 logging 기본값"
    } elseif ($Extension -eq ".pdf") {
        $Role = "승인된 보안 가이드 원문 PDF"
        $Details = "hash·page map·Control source mapping의 기준 원본"
    } elseif ($Extension -in @(".txt", ".conf", ".tmpl", ".mako", ".example")) {
        $Role = "$Stem 텍스트 설정·템플릿"
        $Details = "빌드·실행·검증 도구가 읽는 정적 입력"
    } elseif ($Extension -eq ".qemu-img") {
        $Role = "$Stem VM image 메타데이터"
        $Details = "시험 VM 준비용 image 참조·설정"
    } elseif ($Extension -eq ".patch") {
        $Role = "$Stem 공급망 보정 patch"
        $Details = "잠긴 upstream 구성요소에 적용하는 검토된 최소 수정"
    } else {
        $Role = "$($File.Name) project 설정·보조 파일"
        $Details = "파일명과 상위 폴더 계약에 따라 build·실행·검증에서 사용"
    }

    return [pscustomobject]@{
        Path = $RelativePath
        Name = $File.Name
        Role = ConvertTo-OneLine -Text $Role
        Details = ConvertTo-OneLine -Text $Details
        Note = ConvertTo-OneLine -Text (Get-MaintenanceNote -RelativePath $RelativePath)
    }
}

$OutputDirectory = Split-Path -Parent $ResolvedOutput
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$Files = @(Get-RepositoryFiles | Sort-Object FullName)
$Annotations = @($Files | ForEach-Object { Get-FileAnnotation -File $_ })
$Groups = @($Annotations | Group-Object { Split-Path -Parent $_.Path } | Sort-Object Name)

$Lines = [System.Collections.Generic.List[string]]::new()
$Lines.Add("# Sec_AI 프로젝트 구조·파일 기능 카탈로그")
$Lines.Add("")
$Lines.Add("> 이 문서는 ``tools/generate-repository-catalog.ps1``가 생성한 파일별 세부 주석입니다. 직접 수정하지 말고 source 변경 후 생성기를 다시 실행합니다.")
$Lines.Add("")
$Lines.Add("- 생성 기준일: $(Get-Date -Format 'yyyy-MM-dd')")
$Lines.Add("- 문서화 파일: $($Annotations.Count)개")
$Lines.Add("- 문서화 폴더: $($Groups.Count)개")
$Lines.Add("- 제외: ``.git``·cache·build·``runtime``·``.runtime``·``downloads``·``tmp``·실제 ``.env``·secret·이전 생성 묶음")
$Lines.Add("- 제외 이유: Runtime·VM·비밀정보·대용량 생성물의 내용이나 이름을 문서에 복제하지 않기 위함입니다.")
$Lines.Add("")
$Lines.Add("## 읽는 방법")
$Lines.Add("")
$Lines.Add("- **기능**은 파일의 사용자·Runtime 역할입니다.")
$Lines.Add("- **세부 주석**은 공개 함수·class·대표 계약처럼 변경 영향 분석에 필요한 단서입니다.")
$Lines.Add("- **유지보수 주의**는 해당 파일을 바꿀 때 반드시 지켜야 할 최소 Gate입니다.")
$Lines.Add("- 자동 추출 결과가 코드와 다르면 코드를 먼저 확인하고 생성기의 분류 규칙을 보완합니다.")
$Lines.Add("")
$Lines.Add("## 상위 폴더 요약")
$Lines.Add("")
$Lines.Add("| 폴더 | 파일 수 | 책임 |")
$Lines.Add("|---|---:|---|")
$TopGroups = $Annotations | Group-Object {
    if ($_.Path.Contains("/")) { ($_.Path -split "/")[0] } else { "." }
} | Sort-Object Name
foreach ($Group in $TopGroups) {
    $Folder = if ($Group.Name) { $Group.Name } else { "." }
    $Lines.Add("| ``$Folder`` | $($Group.Count) | $(Get-FolderDescription -Directory $Folder) |")
}

foreach ($Group in $Groups) {
    $Directory = if ([string]::IsNullOrWhiteSpace($Group.Name)) { "." } else { $Group.Name.Replace("\", "/") }
    $Lines.Add("")
    $Lines.Add("## ``$Directory``")
    $Lines.Add("")
    $Lines.Add("> $(Get-FolderDescription -Directory $Directory)")
    $Lines.Add("")
    $Lines.Add("| 파일 | 기능 | 세부 주석 | 유지보수 주의 |")
    $Lines.Add("|---|---|---|---|")
    foreach ($Annotation in ($Group.Group | Sort-Object Name)) {
        $Lines.Add("| ``$($Annotation.Name)`` | $($Annotation.Role) | $($Annotation.Details) | $($Annotation.Note) |")
    }
}

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllLines($ResolvedOutput, $Lines, $Utf8NoBom)

Write-Host "Repository catalog written: $ResolvedOutput"
Write-Host "Documented files: $($Annotations.Count); folders: $($Groups.Count)"
