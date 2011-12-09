ALTER TABLE AdminGroupData DROP COLUMN cAId;

-- Update logging rules
UPDATE AccessRulesData SET accessRule='/secureaudit/auditor/select' WHERE accessRule='/log_functionality/view_log';
UPDATE AccessRulesData SET accessRule='/secureaudit/log_custom_events' WHERE accessRule='/log_functionality/log_custom_events';
UPDATE AccessRulesData SET accessRule='/secureaudit/log' WHERE accessRule='/log_functionality';
UPDATE AccessRulesData SET accessRule='/secureaudit/management/manage' WHERE accessRule='/log_functionality/edit_log_configuration';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/ca_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/ra_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/log_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/publicweb_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/adminweb_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/hardtoken_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/keyrecovery_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/authorization_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/approval_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/services_entries';
DELETE FROM AccessRulesData WHERE accessRule='/log_functionality/view_log/custom_entries';