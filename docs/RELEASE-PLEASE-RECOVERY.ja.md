# Release Please 障害復旧手順

`.github/workflows/release-please.yml` が失敗した場合に使う。release状態を
確定するまで、手順は読み取り専用とする。

## 1. 秘密値を出さずに証跡を採取する

workflow runのURL、試行回数、head SHA、失敗jobのURL、actionのバージョンと
解決済みcommitを記録する。失敗jobのログはGitHubの画面、または次で取得する。

```bash
gh run view RUN_ID --job JOB_ID --log-failed
```

共有するのは該当エラーとGitHubの診断IDだけとする。workflow環境変数、token、
request header、未加工のdebug出力は表示・共有しない。

`gh api rate_limit` で確認できるGraphQL rate limitは、そのコマンドで使った
tokenの値である。workflowの`RELEASE_PLEASE_TOKEN`のquotaや権限を証明しない。

## 2. 再実行前にrelease状態を確定する

想定tagを設定し、読み取り専用の確認を行う。

```bash
TAG=vX.Y.Z
gh repo view --json nameWithOwner
git remote get-url origin
git ls-remote --tags origin "$TAG"
gh release view "$TAG" --json tagName,url,isDraft,isPrerelease,publishedAt
```

結果を解釈する前に、`gh repo view`と`origin`が同じrepositoryを指すことを確認
する。repositoryまたはtagの照会が失敗する、またはrepositoryを検証できない場合、
release状態はunknownである。再実行やrelease変更をせず停止する。repository access
確認後、release照会の明示的なnot-foundだけをrelease不存在と扱い、それ以外の認証、
権限、通信、5xxエラーはunknown stateとする。

結果は分けて解釈する。

- tagまたはGitHub Releaseが存在する場合、pass 1は完了している可能性がある。
  release、asset、後続workflowを確認し、Release Pleaseを無条件に再実行したり
  tag/releaseを作り直したりしない。
- tagの照会が成功してtagなし、かつrepository access確認後のrelease照会が明示的な
  404/not-foundを返す場合、releaseがないことは確定する。ただし不存在だけでは
  pass 1が実行されたか、どこまで進んだかは分からない。失敗stepとログを確認してから、
  手動で1回だけ再実行して安全か判断する。
- job失敗により`release_created`が欠落・利用不能な場合、release未作成の証拠とは
  扱わない。

## 3. 障害を分類する

読み取り専用の既知の一時的GitHub API障害だけを対象にし、release状態を確認した
後、手動承認のうえ上限付きで1回だけ再実行する。例はHTTP 502/503/504、または
一時的なGitHubサービス障害である。

認証、認可、repository access、validation、query不正、原因不明のエラーは再試行
せず失敗として扱う。現行actionの例外retry対象はHTTP 502だけであり、HTTP 200の
GraphQL response内に`errors`がある場合はこの経路の対象外である。

この挙動は実行時の固定action commit
[`45996ed`](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/src/index.ts)で確認済みで、
`package.json`は`release-please` 17.6.0を固定している
([immutableな依存情報](https://github.com/googleapis/release-please-action/blob/45996ed1f6d02564a971a2fa1b5860e934307cf7/package.json))。

`continue-on-error`でworkflowを成功扱いにしない。無制限retryや、
`release_created`欠落だけを理由にしたrelease再実行も行わない。

## 4. 復旧判断

tag/releaseが存在する場合、assetと後続公開workflowを確認する。欠落した個別の
後続成果物だけを、該当する配布手順に従って復旧する。既存tagとreleaseは保持する。

tag/releaseがなく、障害が一時的だと確認できる場合のみ、maintainerがworkflowを
1回再実行できる。再実行後は後続のrelease操作前にtagとreleaseを再確認する。

一時的と明確に判断できない場合はrunを失敗のまま残し、診断IDを記録する。actionの
バージョン、固定commit、正確な時刻、repository、job URL、redact済みエラーを添えて
エスカレーションする。

## 5. pass 1 / pass 2の既知の失敗形態

actionはpass 1でreleaseを作成した後、pass 2のmerge history走査やPR作成で失敗する
場合がある。この場合jobは失敗し、後続処理は`release_created`を安全に利用できない
可能性がある。そのため、再実行前にartifactの存在を直接確認する。

upstream actionの内部retry挙動は、このrepositoryのworkflow設定の範囲外である。障害
復旧の一環として外部actionのfork、vendoring、変更を行わず、必要なら別途設計・レビュー
する。
