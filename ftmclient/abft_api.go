package ftmclient

import (
	"context"
	"math/big"

	"github.com/Fantom-foundation/lachesis-base/inter/idx"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/Fantom-foundation/go-opera/inter"
)

// GetValidators returns Lachesis event by hash or short ID.
func (ec *Client) GetValidators(ctx context.Context, epoch idx.Epoch) (inter.ValidatorProfiles, error) {
	var raw map[hexutil.Uint64]interface{}
	err := ec.c.CallContext(ctx, &raw, "abft_getValidators", toBlockNumArg(big.NewInt(int64(epoch))))
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}

	return inter.RPCUnmarshalValidators(raw)
}
