import { sqliteTable, text, integer, uniqueIndex } from 'drizzle-orm/sqlite-core';
export const incidents = sqliteTable('incidents', {
 id: text('id').primaryKey(), sourceKey: text('source_key').notNull().unique(),
 subject: text('subject').notNull(), sender: text('sender').notNull(),
 receivedAt: text('received_at').notNull(), body: text('body').notNull(),
 analysis: text('analysis').notNull(), status: text('status').notNull().default('Pendiente'),
 evidenceKey: text('evidence_key').notNull(), evidenceHash: text('evidence_hash').notNull(),
 createdAt: text('created_at').notNull(),
 duplicateOf: text('duplicate_of'), groupKey: text('group_key'), revision: integer('revision').notNull().default(0), updatedAt: text('updated_at'),
});
export const operations = sqliteTable('operations', {
 id: text('id').primaryKey(), incidentId: text('incident_id').notNull(),
 action: text('action').notNull(), type: text('type').notNull(), value: text('value').notNull(),
 actor: text('actor').notNull(), reason: text('reason').notNull(),
 state: text('state').notNull(), createdAt: text('created_at').notNull(),
 response: text('response'), httpStatus: integer('http_status'),
}, table => [uniqueIndex('once_per_incident_target_action').on(table.incidentId, table.type, table.value, table.action)]);
export const targetLocks = sqliteTable('target_locks', {
 key: text('key').primaryKey(), operationId: text('operation_id').notNull(),
 createdAt: text('created_at').notNull(),
});
export const alertGroups = sqliteTable('alert_groups', {key:text('key').primaryKey(),incidentId:text('incident_id').notNull()});
export const audit = sqliteTable('audit', {
 id: text('id').primaryKey(), actor: text('actor').notNull(), event: text('event').notNull(),
 detail: text('detail').notNull(), createdAt: text('created_at').notNull(),
});
