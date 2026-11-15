package keys

import "encoding/binary"

const authContext = "otter-auth-v1"

// AuthMessage is the byte string a client signs to log in (docs/02 "Wire details").
func AuthMessage(nodeID, nonce []byte, tsMs int64) []byte {
	m := make([]byte, 0, len(authContext)+len(nodeID)+len(nonce)+8)
	m = append(m, authContext...)
	m = append(m, nodeID...)
	m = append(m, nonce...)
	return binary.BigEndian.AppendUint64(m, uint64(tsMs))
}

const peerContext = "otter-peer-v1"

// PeerAuthMessage is the byte string a node signs during the peer handshake.
func PeerAuthMessage(nodeID, nonce []byte, tsMs int64) []byte {
	m := make([]byte, 0, len(peerContext)+len(nodeID)+len(nonce)+8)
	m = append(m, peerContext...)
	m = append(m, nodeID...)
	m = append(m, nonce...)
	return binary.BigEndian.AppendUint64(m, uint64(tsMs))
}

const adminContext = "otter-admin-v1"

// AdminAuthMessage is what the network key signs for admin.users (M9.2): bound to the node and this connection's
// nonce, so a node cannot replay it elsewhere.
func AdminAuthMessage(nodeID, nonce []byte, tsMs int64) []byte {
	m := make([]byte, 0, len(adminContext)+len(nodeID)+len(nonce)+8)
	m = append(m, adminContext...)
	m = append(m, nodeID...)
	m = append(m, nonce...)
	return binary.BigEndian.AppendUint64(m, uint64(tsMs))
}
