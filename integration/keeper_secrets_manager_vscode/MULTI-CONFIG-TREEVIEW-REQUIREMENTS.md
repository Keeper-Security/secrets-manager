# Multi-Configuration TreeView Requirements Document

## Overview
This document outlines the requirements for implementing a TreeView-based secrets browser with multi-configuration support for the Keeper Secrets Manager VS Code extension.

## Core Requirements Summary

### 1. TreeView Secrets Browser
- **Visual Style**: Dedicated sidebar panel similar to HashiCorp Vault extension
- **Panel Name**: "KSM Devices" 
- **Structure**: Hierarchical folder-based organization matching Keeper's folder structure
- **Display**: Show actual Keeper folders (Shared Folders + Regular Folders), not organized by record type
- **Actions**: View, copy, manage secrets directly from tree

### 2. Multi-Configuration Support
- **Storage**: Array of configurations instead of single config
- **Naming**: Each config displays KSM app name (e.g., "Production (US)")
- **Authentication**: Simultaneous authentication to multiple configs
- **Persistence**: All configurations persist between VS Code restarts
- **Security**: Store all KSM configs securely using VS Code SecretStorage API
- **Methods**: Support One-Time Tokens for adding new KSM devices

### 3. Global User Experience
- **Favorites/Recent**: Global across all configurations (not per-config)
- **Quick Secret Launcher**: Integrate with multi-config system
- **Settings Management**: Manage configurations in VS Code settings page
- **Add/Delete**: Plus button in sidebar + settings page management

## Technical Architecture

### Data Structures

```typescript
interface KSMConfiguration {
  id: string;                    // unique identifier (uuid)
  name: string;                  // KSM app name or user-provided name
  displayName: string;           // formatted display name (e.g., "Production (US)")
  hostname: string;              // keeper region
  authType: 'oneTimeToken' | 'base64Config';
  lastAuth?: Date;               // last authentication time
  secretCount?: number;          // cached secret count
  isAuthenticated: boolean;      // current authentication state
  folders?: KSMFolder[];         // cached folder structure
  records?: KSMRecord[];         // cached secrets
}

interface KSMFolder {
  uid: string;
  name: string;
  type: 'shared' | 'regular';    // Shared Folder (SF) vs Regular Folder (RF)
  parentUid?: string;            // for nested folders
  records: KSMRecord[];          // secrets in this folder
  subfolders: KSMFolder[];       // nested folders
}

interface KSMRecord {
  uid: string;
  title: string;
  folderUid: string;
  fields: KSMField[];
  type: string;                  // record type
}

interface KSMField {
  type: string;
  label: string;
  value: string[];
}
```

### Configuration Storage

```typescript
interface StoredConfigurations {
  activeConfigId?: string;       // currently selected config
  configurations: KSMConfiguration[];
}

// Storage Keys
const STORAGE_KEYS = {
  CONFIGURATIONS: 'keeper.configurations',
  ACTIVE_CONFIG: 'keeper.activeConfig',
  GLOBAL_FAVORITES: 'keeper.globalFavorites',
  GLOBAL_RECENT: 'keeper.globalRecent'
};
```

## Implementation Plan

### Phase 1: Multi-Configuration Foundation

#### 1.1 Configuration Manager Service
Create `src/services/configurationManager.ts`:
- Manage array of KSM configurations
- Secure storage using VS Code SecretStorage API
- Add/remove/update configurations
- Handle authentication state per config
- Get KSM app name from SDK or user input

#### 1.2 Refactor KSMService
Update `src/services/ksmService.ts`:
- Make it configuration-aware (work with specific config)
- Remove global authentication state
- Add methods for per-config operations
- Handle multiple simultaneous connections

#### 1.3 Update Settings Integration
Update `src/services/settingsService.ts`:
- Add multi-config management UI
- Configuration CRUD operations in settings
- Display all configurations with status
- Add/delete configuration actions

### Phase 2: TreeView Implementation

#### 2.1 Secrets Tree Provider
Create `src/providers/secretsTreeProvider.ts`:
- Implement `vscode.TreeDataProvider<TreeItem>`
- Hierarchical display of configurations → folders → records
- Tree item types: Configuration, Folder, Record
- Refresh capabilities for real-time updates
- Lazy loading for performance

#### 2.2 Tree View UI
Tree structure:
```
KSM Devices
├── 🔐 Production (US) [authenticated]
│   ├── 📁 Database (SF)
│   │   ├── 🔑 postgres-prod
│   │   └── 🔑 redis-cache
│   ├── 📁 API Keys (SF)
│   │   └── 🔑 stripe-key
│   └── 📁 Personal (RF)
│       └── 🔑 dev-token
├── 🔐 Development (EU) [not authenticated]
│   └── 📁 Loading... (authenticate to view)
└── ➕ Add New Configuration
```

#### 2.3 Tree Actions
Context menu and inline actions:
- **Configuration Level**: Authenticate, Refresh, Rename, Delete
- **Folder Level**: Expand/Collapse, Create Record
- **Record Level**: Copy Field, View Details, Edit, Delete
- **Global**: Add Configuration, Refresh All

### Phase 3: Integration & Polish

#### 3.1 Update Existing Services
- **QuickAccessService**: Work with multi-config system
- **TerminalDetectionService**: Respect configuration context
- **Status Bar**: Show active configuration
- **Commands**: Update all commands to work with active config

#### 3.2 Settings Page Integration
Add to VS Code settings:
```json
{
  "keeper.configurations": [
    {
      "id": "uuid-1",
      "name": "Production",
      "displayName": "Production (US)",
      "hostname": "keepersecurity.com",
      "authType": "oneTimeToken",
      "lastAuth": "2024-07-18T10:30:00Z",
      "isAuthenticated": true,
      "secretCount": 45
    }
  ],
  "keeper.activeConfiguration": "uuid-1"
}
```

#### 3.3 Migration Strategy
For existing users:
1. Detect existing single configuration
2. Create default configuration object
3. Migrate existing auth to new structure
4. Set as active configuration
5. Show migration success message

## KSM App Name Resolution

### Primary Method: SDK Metadata
Try to extract app name from KSM SDK:
```typescript
// Check if KeeperSecrets object has metadata
const result: KeeperSecrets = await getSecrets(options);
const appName = result.appName || result.metadata?.appName || null;
```

### Fallback Methods:
1. **User Input**: Prompt user for friendly name during config creation
2. **Hostname-Based**: Generate name from hostname ("US Production", "EU Development")
3. **Default Pattern**: "KSM Device {N}" where N is sequence number

### Name Format:
- Display as: "{AppName} ({Region})"
- Examples: "Production (US)", "Development (EU)", "KSM Device 1 (US)"

## Security Considerations

### Secure Storage
- All configurations stored in VS Code SecretStorage (OS-native encryption)
- No plaintext credentials in settings or workspace
- Individual encryption per configuration

### Authentication Persistence
- Each configuration maintains separate authentication state
- Auto-refresh authentication before expiration
- Secure token storage per configuration

### Error Handling
- Graceful handling of authentication failures
- Clear error messages for configuration issues
- Automatic retry mechanisms for network issues

## User Experience

### Adding New Configuration
1. Click "➕ Add New Configuration" in tree
2. OR use "Keeper: Add KSM Device" command
3. OR go to Settings → Keeper → "Add Configuration"
4. Enter One-Time Token or Base64 config
5. Optionally provide friendly name
6. Auto-detect or prompt for app name
7. Save securely and authenticate

### Configuration Management
- Settings page shows all configurations
- Each config shows: Name, Status, Last Auth, Secret Count
- Actions: Edit Name, Re-authenticate, Delete
- Active configuration highlighted

### TreeView Usage
- Expand/collapse configurations
- Click to authenticate if needed
- Browse folders and records
- Right-click for context actions
- Drag-and-drop support (future)

## Integration Points

### Quick Secret Launcher
- Show secrets from all authenticated configurations
- Group by configuration in search results
- Indicate source configuration for each secret
- Maintain global favorites across configs

### Status Bar
- Show active configuration name
- Click to open configuration picker
- Visual indicator for authentication status
- Quick access to tree view

### Commands Integration
- All existing commands work with active configuration
- New commands: "Select Active Configuration", "Add KSM Device"
- Configuration context preserved across commands

## Performance Considerations

### Lazy Loading
- Load folder contents on demand
- Cache folder structure per configuration
- Refresh only when necessary

### Background Refresh
- Auto-refresh configurations periodically
- Update secret counts in background
- Maintain authentication state

### Memory Management
- Efficient caching of folder structures
- Clear unused configuration data
- Optimize for large numbers of secrets

## Testing Requirements

### Unit Tests
- ConfigurationManager CRUD operations
- SecretTreeProvider data transformation
- Authentication state management
- Settings integration

### Integration Tests
- Multi-config authentication flows
- TreeView user interactions
- Settings page functionality
- Migration from single to multi-config

### Security Tests
- Secure storage verification
- Authentication persistence tests
- Error handling security
- Token validation

## Documentation Updates

### README.md
- New TreeView section with screenshots
- Multi-configuration setup guide
- Migration instructions for existing users
- Updated command reference

### PRD
- Complete feature specification
- User stories for multi-config usage
- Technical architecture documentation
- Success metrics and KPIs

## Implementation Timeline

### Week 1: Foundation
- Configuration Manager service
- Multi-config storage implementation
- KSMService refactoring
- Basic settings integration

### Week 2: TreeView
- Secrets Tree Provider implementation
- Tree view UI and actions
- Context menus and commands
- Basic folder navigation

### Week 3: Integration
- Update existing services
- Status bar integration
- Quick Secret Launcher updates
- Command integration

### Week 4: Polish & Testing
- Migration strategy implementation
- Error handling improvements
- Performance optimization
- Documentation updates

## Success Metrics

### User Adoption
- 80% of users adopt TreeView within 30 days
- 60% of users configure multiple devices
- 90% user satisfaction with folder navigation

### Performance
- TreeView loads in <500ms for 100+ secrets
- Configuration switching in <200ms
- Zero data loss during multi-config operations

### Security
- 100% secure storage compliance
- Zero authentication state leaks
- Successful migration for all existing users

## Risk Mitigation

### Technical Risks
- **KSM SDK Limitations**: Fallback to user-provided names
- **Authentication Complexity**: Implement robust error handling
- **Performance Issues**: Lazy loading and caching strategies

### User Experience Risks
- **Migration Confusion**: Clear upgrade path and documentation
- **Complexity Increase**: Intuitive UI design and helpful tooltips
- **Data Loss**: Comprehensive backup and restore mechanisms

---

**Note**: This document serves as the comprehensive specification for implementing multi-configuration TreeView support. All implementation should reference this document for requirements and technical details.