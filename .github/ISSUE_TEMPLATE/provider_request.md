---
name: New OAuth Provider Request
about: Request support for a new OAuth 2.0 provider
title: '[PROVIDER] Add support for [Provider Name]'
labels: 'provider', 'enhancement'
assignees: ''

---

**Provider Information**
- **Provider Name**: [e.g. GitHub, Slack, Dropbox, LinkedIn]
- **Provider Website**: [e.g. https://github.com]
- **OAuth Documentation**: [link to provider's OAuth 2.0 documentation]
- **API Documentation**: [link to provider's API documentation]

**OAuth 2.0 Details**
- **Authorization URL**: [e.g. https://github.com/login/oauth/authorize]
- **Token URL**: [e.g. https://github.com/login/oauth/access_token]
- **OAuth Version**: [e.g. OAuth 2.0, OAuth 2.1]
- **Supported Grant Types**: [e.g. authorization_code, refresh_token]

**Required Scopes**
List the OAuth scopes that would be useful for AI agents:
- [ ] `scope1` - Description of what this scope provides
- [ ] `scope2` - Description of what this scope provides
- [ ] `scope3` - Description of what this scope provides

**Use Cases**
Describe how AI agents would use this provider's data:
- **Email/Communication**: [if applicable]
- **Calendar/Scheduling**: [if applicable]
- **File Storage**: [if applicable]
- **Social Media**: [if applicable]
- **Development Tools**: [if applicable]
- **Other**: [describe specific use cases]

**API Capabilities**
What data/actions would be available through this provider's API?
- [ ] Read user profile information
- [ ] Access user's files/documents
- [ ] Read/send messages or communications
- [ ] Manage calendar events
- [ ] Access repositories or projects
- [ ] Other: [specify]

**Implementation Considerations**
- **Rate Limits**: [any known rate limiting information]
- **Authentication Method**: [API key, Bearer token, etc.]
- **Special Requirements**: [any unique OAuth flow requirements]
- **PKCE Support**: [does the provider support PKCE?]
- **Refresh Token Support**: [does the provider issue refresh tokens?]

**Community Interest**
- **Priority for your use case**: [High/Medium/Low]
- **Willing to help implement**: [Yes/No]
- **Willing to test**: [Yes/No]
- **Have OAuth app credentials for testing**: [Yes/No]

**Additional Context**
Add any other context about this provider request:
- Similar providers already supported
- Specific agent workflows this would enable
- Enterprise or business use cases
- Community demand or requests

**Checklist:**
- [ ] I have searched existing issues to ensure this provider isn't already requested
- [ ] I have provided links to the provider's OAuth documentation
- [ ] I have identified specific use cases for AI agents
- [ ] I have checked that the provider supports OAuth 2.0
- [ ] I understand this is a community-driven project and implementation may take time