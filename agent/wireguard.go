package agent

import (
	"context"

	"golang.org/x/xerrors"
	"inet.af/netaddr"

	"github.com/coder/coder/peer/peerwg"

	"cdr.dev/slog"
)

func (a *agent) startWireguard(ctx context.Context, addrs []netaddr.IPPrefix) error {
	if a.wg != nil {
		_ = a.wg.Close()
	}

	wg, err := peerwg.NewWireguardNetwork(ctx, a.logger.Named("wireguard"), addrs)
	if err != nil {
		return xerrors.Errorf("create wireguard network: %w", err)
	}

	err = a.postKeys(ctx, PublicKeys{
		Public: wg.Private.Public(),
		Disco:  wg.Disco,
	})
	if err != nil {
		a.logger.Warn(ctx, "post keys", slog.Error(err))
	}

	go func() {
		for {
			ch, listenClose, err := a.listenWireguardPeers(ctx, a.logger)
			if err != nil {
				a.logger.Warn(ctx, "listen wireguard peers", slog.Error(err))
				return
			}

			for {
				peer := <-ch
				if peer == nil {
					break
				}

				err := wg.AddPeer(*peer)
				a.logger.Info(ctx, "added wireguard peer", slog.F("peer", peer.Public.ShortString()), slog.Error(err))
			}

			listenClose()
		}
	}()

	a.wg = wg
	return nil
}
