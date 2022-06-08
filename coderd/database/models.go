// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.13.0

package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tabbed/pqtype"
)

type AuditAction string

const (
	AuditActionCreate AuditAction = "create"
	AuditActionWrite  AuditAction = "write"
	AuditActionDelete AuditAction = "delete"
)

func (e *AuditAction) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AuditAction(s)
	case string:
		*e = AuditAction(s)
	default:
		return fmt.Errorf("unsupported scan type for AuditAction: %T", src)
	}
	return nil
}

type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

func (e *LogLevel) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = LogLevel(s)
	case string:
		*e = LogLevel(s)
	default:
		return fmt.Errorf("unsupported scan type for LogLevel: %T", src)
	}
	return nil
}

type LogSource string

const (
	LogSourceProvisionerDaemon LogSource = "provisioner_daemon"
	LogSourceProvisioner       LogSource = "provisioner"
)

func (e *LogSource) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = LogSource(s)
	case string:
		*e = LogSource(s)
	default:
		return fmt.Errorf("unsupported scan type for LogSource: %T", src)
	}
	return nil
}

type LoginType string

const (
	LoginTypePassword LoginType = "password"
	LoginTypeGithub   LoginType = "github"
)

func (e *LoginType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = LoginType(s)
	case string:
		*e = LoginType(s)
	default:
		return fmt.Errorf("unsupported scan type for LoginType: %T", src)
	}
	return nil
}

type ParameterDestinationScheme string

const (
	ParameterDestinationSchemeNone                ParameterDestinationScheme = "none"
	ParameterDestinationSchemeEnvironmentVariable ParameterDestinationScheme = "environment_variable"
	ParameterDestinationSchemeProvisionerVariable ParameterDestinationScheme = "provisioner_variable"
)

func (e *ParameterDestinationScheme) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ParameterDestinationScheme(s)
	case string:
		*e = ParameterDestinationScheme(s)
	default:
		return fmt.Errorf("unsupported scan type for ParameterDestinationScheme: %T", src)
	}
	return nil
}

type ParameterScope string

const (
	ParameterScopeTemplate  ParameterScope = "template"
	ParameterScopeImportJob ParameterScope = "import_job"
	ParameterScopeWorkspace ParameterScope = "workspace"
)

func (e *ParameterScope) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ParameterScope(s)
	case string:
		*e = ParameterScope(s)
	default:
		return fmt.Errorf("unsupported scan type for ParameterScope: %T", src)
	}
	return nil
}

type ParameterSourceScheme string

const (
	ParameterSourceSchemeNone ParameterSourceScheme = "none"
	ParameterSourceSchemeData ParameterSourceScheme = "data"
)

func (e *ParameterSourceScheme) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ParameterSourceScheme(s)
	case string:
		*e = ParameterSourceScheme(s)
	default:
		return fmt.Errorf("unsupported scan type for ParameterSourceScheme: %T", src)
	}
	return nil
}

type ParameterTypeSystem string

const (
	ParameterTypeSystemNone ParameterTypeSystem = "none"
	ParameterTypeSystemHCL  ParameterTypeSystem = "hcl"
)

func (e *ParameterTypeSystem) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ParameterTypeSystem(s)
	case string:
		*e = ParameterTypeSystem(s)
	default:
		return fmt.Errorf("unsupported scan type for ParameterTypeSystem: %T", src)
	}
	return nil
}

type ProvisionerJobType string

const (
	ProvisionerJobTypeTemplateVersionImport ProvisionerJobType = "template_version_import"
	ProvisionerJobTypeWorkspaceBuild        ProvisionerJobType = "workspace_build"
	ProvisionerJobTypeTemplateVersionDryRun ProvisionerJobType = "template_version_dry_run"
)

func (e *ProvisionerJobType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ProvisionerJobType(s)
	case string:
		*e = ProvisionerJobType(s)
	default:
		return fmt.Errorf("unsupported scan type for ProvisionerJobType: %T", src)
	}
	return nil
}

type ProvisionerStorageMethod string

const (
	ProvisionerStorageMethodFile ProvisionerStorageMethod = "file"
)

func (e *ProvisionerStorageMethod) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ProvisionerStorageMethod(s)
	case string:
		*e = ProvisionerStorageMethod(s)
	default:
		return fmt.Errorf("unsupported scan type for ProvisionerStorageMethod: %T", src)
	}
	return nil
}

type ProvisionerType string

const (
	ProvisionerTypeEcho      ProvisionerType = "echo"
	ProvisionerTypeTerraform ProvisionerType = "terraform"
)

func (e *ProvisionerType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ProvisionerType(s)
	case string:
		*e = ProvisionerType(s)
	default:
		return fmt.Errorf("unsupported scan type for ProvisionerType: %T", src)
	}
	return nil
}

type ResourceType string

const (
	ResourceTypeOrganization    ResourceType = "organization"
	ResourceTypeTemplate        ResourceType = "template"
	ResourceTypeTemplateVersion ResourceType = "template_version"
	ResourceTypeUser            ResourceType = "user"
	ResourceTypeWorkspace       ResourceType = "workspace"
)

func (e *ResourceType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ResourceType(s)
	case string:
		*e = ResourceType(s)
	default:
		return fmt.Errorf("unsupported scan type for ResourceType: %T", src)
	}
	return nil
}

type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
)

func (e *UserStatus) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = UserStatus(s)
	case string:
		*e = UserStatus(s)
	default:
		return fmt.Errorf("unsupported scan type for UserStatus: %T", src)
	}
	return nil
}

type WorkspaceTransition string

const (
	WorkspaceTransitionStart  WorkspaceTransition = "start"
	WorkspaceTransitionStop   WorkspaceTransition = "stop"
	WorkspaceTransitionDelete WorkspaceTransition = "delete"
)

func (e *WorkspaceTransition) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = WorkspaceTransition(s)
	case string:
		*e = WorkspaceTransition(s)
	default:
		return fmt.Errorf("unsupported scan type for WorkspaceTransition: %T", src)
	}
	return nil
}

type APIKey struct {
	ID                string    `db:"id" json:"id"`
	HashedSecret      []byte    `db:"hashed_secret" json:"hashed_secret"`
	UserID            uuid.UUID `db:"user_id" json:"user_id"`
	LastUsed          time.Time `db:"last_used" json:"last_used"`
	ExpiresAt         time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt         time.Time `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time `db:"updated_at" json:"updated_at"`
	LoginType         LoginType `db:"login_type" json:"login_type"`
	OAuthAccessToken  string    `db:"oauth_access_token" json:"oauth_access_token"`
	OAuthRefreshToken string    `db:"oauth_refresh_token" json:"oauth_refresh_token"`
	OAuthIDToken      string    `db:"oauth_id_token" json:"oauth_id_token"`
	OAuthExpiry       time.Time `db:"oauth_expiry" json:"oauth_expiry"`
	LifetimeSeconds   int64     `db:"lifetime_seconds" json:"lifetime_seconds"`
}

type AuditLog struct {
	ID             uuid.UUID       `db:"id" json:"id"`
	Time           time.Time       `db:"time" json:"time"`
	UserID         uuid.UUID       `db:"user_id" json:"user_id"`
	OrganizationID uuid.UUID       `db:"organization_id" json:"organization_id"`
	Ip             pqtype.Inet     `db:"ip" json:"ip"`
	UserAgent      string          `db:"user_agent" json:"user_agent"`
	ResourceType   ResourceType    `db:"resource_type" json:"resource_type"`
	ResourceID     uuid.UUID       `db:"resource_id" json:"resource_id"`
	ResourceTarget string          `db:"resource_target" json:"resource_target"`
	Action         AuditAction     `db:"action" json:"action"`
	Diff           json.RawMessage `db:"diff" json:"diff"`
	StatusCode     int32           `db:"status_code" json:"status_code"`
}

type File struct {
	Hash      string    `db:"hash" json:"hash"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	CreatedBy uuid.UUID `db:"created_by" json:"created_by"`
	Mimetype  string    `db:"mimetype" json:"mimetype"`
	Data      []byte    `db:"data" json:"data"`
}

type GitSSHKey struct {
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
	PrivateKey string    `db:"private_key" json:"private_key"`
	PublicKey  string    `db:"public_key" json:"public_key"`
}

type License struct {
	ID        int32           `db:"id" json:"id"`
	License   json.RawMessage `db:"license" json:"license"`
	CreatedAt time.Time       `db:"created_at" json:"created_at"`
}

type Organization struct {
	ID          uuid.UUID `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at" json:"updated_at"`
}

type OrganizationMember struct {
	UserID         uuid.UUID `db:"user_id" json:"user_id"`
	OrganizationID uuid.UUID `db:"organization_id" json:"organization_id"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
	Roles          []string  `db:"roles" json:"roles"`
}

type ParameterSchema struct {
	ID                       uuid.UUID                  `db:"id" json:"id"`
	CreatedAt                time.Time                  `db:"created_at" json:"created_at"`
	JobID                    uuid.UUID                  `db:"job_id" json:"job_id"`
	Name                     string                     `db:"name" json:"name"`
	Description              string                     `db:"description" json:"description"`
	DefaultSourceScheme      ParameterSourceScheme      `db:"default_source_scheme" json:"default_source_scheme"`
	DefaultSourceValue       string                     `db:"default_source_value" json:"default_source_value"`
	AllowOverrideSource      bool                       `db:"allow_override_source" json:"allow_override_source"`
	DefaultDestinationScheme ParameterDestinationScheme `db:"default_destination_scheme" json:"default_destination_scheme"`
	AllowOverrideDestination bool                       `db:"allow_override_destination" json:"allow_override_destination"`
	DefaultRefresh           string                     `db:"default_refresh" json:"default_refresh"`
	RedisplayValue           bool                       `db:"redisplay_value" json:"redisplay_value"`
	ValidationError          string                     `db:"validation_error" json:"validation_error"`
	ValidationCondition      string                     `db:"validation_condition" json:"validation_condition"`
	ValidationTypeSystem     ParameterTypeSystem        `db:"validation_type_system" json:"validation_type_system"`
	ValidationValueType      string                     `db:"validation_value_type" json:"validation_value_type"`
}

type ParameterValue struct {
	ID                uuid.UUID                  `db:"id" json:"id"`
	CreatedAt         time.Time                  `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time                  `db:"updated_at" json:"updated_at"`
	Scope             ParameterScope             `db:"scope" json:"scope"`
	ScopeID           uuid.UUID                  `db:"scope_id" json:"scope_id"`
	Name              string                     `db:"name" json:"name"`
	SourceScheme      ParameterSourceScheme      `db:"source_scheme" json:"source_scheme"`
	SourceValue       string                     `db:"source_value" json:"source_value"`
	DestinationScheme ParameterDestinationScheme `db:"destination_scheme" json:"destination_scheme"`
}

type ProvisionerDaemon struct {
	ID           uuid.UUID         `db:"id" json:"id"`
	CreatedAt    time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt    sql.NullTime      `db:"updated_at" json:"updated_at"`
	Name         string            `db:"name" json:"name"`
	Provisioners []ProvisionerType `db:"provisioners" json:"provisioners"`
}

type ProvisionerJob struct {
	ID             uuid.UUID                `db:"id" json:"id"`
	CreatedAt      time.Time                `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time                `db:"updated_at" json:"updated_at"`
	StartedAt      sql.NullTime             `db:"started_at" json:"started_at"`
	CanceledAt     sql.NullTime             `db:"canceled_at" json:"canceled_at"`
	CompletedAt    sql.NullTime             `db:"completed_at" json:"completed_at"`
	Error          sql.NullString           `db:"error" json:"error"`
	OrganizationID uuid.UUID                `db:"organization_id" json:"organization_id"`
	InitiatorID    uuid.UUID                `db:"initiator_id" json:"initiator_id"`
	Provisioner    ProvisionerType          `db:"provisioner" json:"provisioner"`
	StorageMethod  ProvisionerStorageMethod `db:"storage_method" json:"storage_method"`
	StorageSource  string                   `db:"storage_source" json:"storage_source"`
	Type           ProvisionerJobType       `db:"type" json:"type"`
	Input          json.RawMessage          `db:"input" json:"input"`
	WorkerID       uuid.NullUUID            `db:"worker_id" json:"worker_id"`
}

type ProvisionerJobLog struct {
	ID        uuid.UUID `db:"id" json:"id"`
	JobID     uuid.UUID `db:"job_id" json:"job_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	Source    LogSource `db:"source" json:"source"`
	Level     LogLevel  `db:"level" json:"level"`
	Stage     string    `db:"stage" json:"stage"`
	Output    string    `db:"output" json:"output"`
}

type Template struct {
	ID                   uuid.UUID       `db:"id" json:"id"`
	CreatedAt            time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time       `db:"updated_at" json:"updated_at"`
	OrganizationID       uuid.UUID       `db:"organization_id" json:"organization_id"`
	Deleted              bool            `db:"deleted" json:"deleted"`
	Name                 string          `db:"name" json:"name"`
	Provisioner          ProvisionerType `db:"provisioner" json:"provisioner"`
	ActiveVersionID      uuid.UUID       `db:"active_version_id" json:"active_version_id"`
	Description          string          `db:"description" json:"description"`
	MaxTtl               int64           `db:"max_ttl" json:"max_ttl"`
	MinAutostartInterval int64           `db:"min_autostart_interval" json:"min_autostart_interval"`
}

type TemplateVersion struct {
	ID             uuid.UUID     `db:"id" json:"id"`
	TemplateID     uuid.NullUUID `db:"template_id" json:"template_id"`
	OrganizationID uuid.UUID     `db:"organization_id" json:"organization_id"`
	CreatedAt      time.Time     `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time     `db:"updated_at" json:"updated_at"`
	Name           string        `db:"name" json:"name"`
	Readme         string        `db:"readme" json:"readme"`
	JobID          uuid.UUID     `db:"job_id" json:"job_id"`
}

type User struct {
	ID             uuid.UUID  `db:"id" json:"id"`
	Email          string     `db:"email" json:"email"`
	Username       string     `db:"username" json:"username"`
	HashedPassword []byte     `db:"hashed_password" json:"hashed_password"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time  `db:"updated_at" json:"updated_at"`
	Status         UserStatus `db:"status" json:"status"`
	RBACRoles      []string   `db:"rbac_roles" json:"rbac_roles"`
}

type Workspace struct {
	ID                uuid.UUID      `db:"id" json:"id"`
	CreatedAt         time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time      `db:"updated_at" json:"updated_at"`
	OwnerID           uuid.UUID      `db:"owner_id" json:"owner_id"`
	OrganizationID    uuid.UUID      `db:"organization_id" json:"organization_id"`
	TemplateID        uuid.UUID      `db:"template_id" json:"template_id"`
	Deleted           bool           `db:"deleted" json:"deleted"`
	Name              string         `db:"name" json:"name"`
	AutostartSchedule sql.NullString `db:"autostart_schedule" json:"autostart_schedule"`
	Ttl               sql.NullInt64  `db:"ttl" json:"ttl"`
}

type WorkspaceAgent struct {
	ID                   uuid.UUID             `db:"id" json:"id"`
	CreatedAt            time.Time             `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time             `db:"updated_at" json:"updated_at"`
	Name                 string                `db:"name" json:"name"`
	FirstConnectedAt     sql.NullTime          `db:"first_connected_at" json:"first_connected_at"`
	LastConnectedAt      sql.NullTime          `db:"last_connected_at" json:"last_connected_at"`
	DisconnectedAt       sql.NullTime          `db:"disconnected_at" json:"disconnected_at"`
	ResourceID           uuid.UUID             `db:"resource_id" json:"resource_id"`
	AuthToken            uuid.UUID             `db:"auth_token" json:"auth_token"`
	AuthInstanceID       sql.NullString        `db:"auth_instance_id" json:"auth_instance_id"`
	Architecture         string                `db:"architecture" json:"architecture"`
	EnvironmentVariables pqtype.NullRawMessage `db:"environment_variables" json:"environment_variables"`
	OperatingSystem      string                `db:"operating_system" json:"operating_system"`
	StartupScript        sql.NullString        `db:"startup_script" json:"startup_script"`
	InstanceMetadata     pqtype.NullRawMessage `db:"instance_metadata" json:"instance_metadata"`
	ResourceMetadata     pqtype.NullRawMessage `db:"resource_metadata" json:"resource_metadata"`
	Directory            string                `db:"directory" json:"directory"`
}

type WorkspaceApp struct {
	ID           uuid.UUID      `db:"id" json:"id"`
	CreatedAt    time.Time      `db:"created_at" json:"created_at"`
	AgentID      uuid.UUID      `db:"agent_id" json:"agent_id"`
	Name         string         `db:"name" json:"name"`
	Icon         string         `db:"icon" json:"icon"`
	Command      sql.NullString `db:"command" json:"command"`
	Url          sql.NullString `db:"url" json:"url"`
	RelativePath bool           `db:"relative_path" json:"relative_path"`
}

type WorkspaceBuild struct {
	ID                uuid.UUID           `db:"id" json:"id"`
	CreatedAt         time.Time           `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time           `db:"updated_at" json:"updated_at"`
	WorkspaceID       uuid.UUID           `db:"workspace_id" json:"workspace_id"`
	TemplateVersionID uuid.UUID           `db:"template_version_id" json:"template_version_id"`
	Name              string              `db:"name" json:"name"`
	BuildNumber       int32               `db:"build_number" json:"build_number"`
	Transition        WorkspaceTransition `db:"transition" json:"transition"`
	InitiatorID       uuid.UUID           `db:"initiator_id" json:"initiator_id"`
	ProvisionerState  []byte              `db:"provisioner_state" json:"provisioner_state"`
	JobID             uuid.UUID           `db:"job_id" json:"job_id"`
	Deadline          time.Time           `db:"deadline" json:"deadline"`
}

type WorkspaceBuildWithName struct {
	InitiatorUsername     string              `db:"initiator_username" json:"initiator_username"`
	OwnerID               uuid.UUID           `db:"owner_id" json:"owner_id"`
	OwnerName             string              `db:"owner_name" json:"owner_name"`
	WorkspaceName         string              `db:"workspace_name" json:"workspace_name"`
	TemplateID            uuid.UUID           `db:"template_id" json:"template_id"`
	TemplateName          string              `db:"template_name" json:"template_name"`
	TemplateActiveVersion uuid.UUID           `db:"template_active_version" json:"template_active_version"`
	ID                    uuid.UUID           `db:"id" json:"id"`
	CreatedAt             time.Time           `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time           `db:"updated_at" json:"updated_at"`
	WorkspaceID           uuid.UUID           `db:"workspace_id" json:"workspace_id"`
	TemplateVersionID     uuid.UUID           `db:"template_version_id" json:"template_version_id"`
	Name                  string              `db:"name" json:"name"`
	BuildNumber           int32               `db:"build_number" json:"build_number"`
	Transition            WorkspaceTransition `db:"transition" json:"transition"`
	InitiatorID           uuid.UUID           `db:"initiator_id" json:"initiator_id"`
	ProvisionerState      []byte              `db:"provisioner_state" json:"provisioner_state"`
	JobID                 uuid.UUID           `db:"job_id" json:"job_id"`
	Deadline              time.Time           `db:"deadline" json:"deadline"`
}

type WorkspaceResource struct {
	ID         uuid.UUID           `db:"id" json:"id"`
	CreatedAt  time.Time           `db:"created_at" json:"created_at"`
	JobID      uuid.UUID           `db:"job_id" json:"job_id"`
	Transition WorkspaceTransition `db:"transition" json:"transition"`
	Type       string              `db:"type" json:"type"`
	Name       string              `db:"name" json:"name"`
}
