package authz

// TODO: Implement Authorize
func Authorize(subj Subject, obj Resource, action Action) error {
	// TODO: Expand subject roles into their permissions as appropriate. Apply scopes.
	return AuthorizePermissions(subj.ID(), []Permission{}, obj, action)
}

// AuthorizePermissions runs the authorize function with the raw permissions in a single list.
func AuthorizePermissions(subjID string, permissions []Permission, object Resource, action Action) error {

	return nil
}
