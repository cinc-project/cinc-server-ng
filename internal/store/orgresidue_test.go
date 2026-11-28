package store

import "testing"

// plantResidue leaves rows under org without it existing, as a write that
// raced the org's deletion could before writes were refused, or as a database
// written by an older version may still hold.
func plantResidue(m *memoryBackend, org string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store(org, "clients", "ghost", []byte(`{}`), Meta{UpdatedBy: "clients/ghost"})
	m.store(org, "group_members", "clients\x00clients\x00ghost", []byte(`{}`), Meta{})
	if m.blobs[org] == nil {
		m.blobs[org] = map[string][]byte{}
	}
	m.blobs[org]["cafe"] = []byte("x")
}

func wantNoResidue(t *testing.T, b Backend, org string) {
	t.Helper()
	if colls, err := b.Collections(org); err != nil || len(colls) != 0 {
		t.Fatalf("Collections = %v (%v), want none", colls, err)
	}
	if _, ok, _ := b.Meta(org, "clients", "ghost"); ok {
		t.Fatal("residue metadata survived CreateOrg")
	}
	if ok, _ := b.HasBlob(org, "cafe"); ok {
		t.Fatal("residue blob survived CreateOrg")
	}
}

// TestMemoryCreateOrgPurgesResidue asserts a created org starts empty even if
// rows were left under its name.
func TestMemoryCreateOrgPurgesResidue(t *testing.T) {
	m := NewMemoryBackend().(*memoryBackend)
	plantResidue(m, "acme")
	if err := m.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	wantNoResidue(t, m, "acme")
}

// TestMemoryTxCreateOrgPurgesResidue is the same through a transaction, as
// the API creates organizations: inside it and after it commits.
func TestMemoryTxCreateOrgPurgesResidue(t *testing.T) {
	m := NewMemoryBackend().(*memoryBackend)
	plantResidue(m, "acme")
	if err := m.Tx(func(tx Backend) error {
		if err := tx.CreateOrg("acme"); err != nil {
			return err
		}
		wantNoResidue(t, tx, "acme")
		return tx.Put("acme", "nodes", "web", []byte(`{}`), Stamp{})
	}); err != nil {
		t.Fatal(err)
	}
	if colls, _ := m.Collections("acme"); len(colls) != 1 || colls[0] != "nodes" {
		t.Fatalf("Collections = %v, want [nodes]", colls)
	}
	if ok, _ := m.HasBlob("acme", "cafe"); ok {
		t.Fatal("residue blob survived the transaction's CreateOrg")
	}
}

// TestStoreCreateOrgResetsDerivedIndexes asserts creating an org tells the
// derived indexes to drop anything they hold under its name.
func TestStoreCreateOrgResetsDerivedIndexes(t *testing.T) {
	s := New()
	var got []Event
	s.Watch(func(ev Event) { got = append(got, ev) })
	if err := s.Tx(func(tx *Store) error {
		_, err := tx.CreateOrg("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Org != "acme" || got[0].Collection != "" || !got[0].Deleted {
		t.Fatalf("events = %+v, want an org-wide drop of acme first", got)
	}
}
