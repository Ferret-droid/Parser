import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Text, 
  TextInput, 
  Textarea, 
  Button, 
  Group, 
  Paper, 
  Title, 
  Tabs, 
  MultiSelect,
  ActionIcon,
  Divider,
  Badge,
  Card
} from '@mantine/core';
import { IconPlus, IconTrash, IconSave, IconRefresh } from '@tabler/icons-react';
import { useForm } from '@mantine/form';

const KeywordDictionaryForm = ({ 
  dictionary = null, 
  onSubmit, 
  isLoading = false,
  projects = []
}) => {
  // Initialize form with empty values or existing dictionary
  const form = useForm({
    initialValues: {
      name: dictionary?.name || '',
      description: dictionary?.description || '',
      project_id: dictionary?.project_id || '',
      identifier_keywords: dictionary?.identifier_keywords || [],
      global_keywords: dictionary?.global_keywords || [],
      high_confidence_keywords: dictionary?.high_confidence_keywords || [],
      general_keywords: dictionary?.general_keywords || []
    },
    validate: {
      name: (value) => (!value ? 'Name is required' : null),
      project_id: (value) => (!value ? 'Project is required' : null),
    }
  });

  // Handle new keyword input
  const [newKeyword, setNewKeyword] = useState('');
  const [activeTab, setActiveTab] = useState('identifier');

  // Add a keyword to the selected category
  const addKeyword = () => {
    if (!newKeyword.trim()) return;
    
    const fieldName = `${activeTab}_keywords`;
    
    // Add keyword if it doesn't already exist
    if (!form.values[fieldName].includes(newKeyword.trim())) {
      form.setFieldValue(fieldName, [
        ...form.values[fieldName],
        newKeyword.trim()
      ]);
    }
    
    // Clear the input
    setNewKeyword('');
  };

  // Remove a keyword from a category
  const removeKeyword = (category, keyword) => {
    const fieldName = `${category}_keywords`;
    form.setFieldValue(
      fieldName, 
      form.values[fieldName].filter(k => k !== keyword)
    );
  };

  // Handle form submission
  const handleSubmit = form.onSubmit((values) => {
    onSubmit(values);
  });

  return (
    <Box>
      <Paper p="md" radius="md" withBorder>
        <Title order={3} mb="md">
          {dictionary ? 'Edit Keyword Dictionary' : 'Create Keyword Dictionary'}
        </Title>
        
        <form onSubmit={handleSubmit}>
          <Group grow mb="md">
            <TextInput
              label="Dictionary Name"
              placeholder="Enter a name for this dictionary"
              required
              {...form.getInputProps('name')}
            />
            
            <select
              {...form.getInputProps('project_id')}
              className="mantine-Select-input mantine-Select-wrapper"
              style={{ height: 36, marginTop: 22 }}
            >
              <option value="">Select Project</option>
              {projects.map(project => (
                <option key={project.id} value={project.id}>
                  {project.name}
                </option>
              ))}
            </select>
          </Group>
          
          <Textarea
            label="Description"
            placeholder="Describe the purpose of this keyword dictionary"
            mb="md"
            minRows={3}
            {...form.getInputProps('description')}
          />
          
          <Divider my="md" label="Keyword Categories" labelPosition="center" />
          
          <Tabs value={activeTab} onChange={setActiveTab}>
            <Tabs.List>
              <Tabs.Tab value="identifier" color="red">
                Identifiers
                <Badge ml="xs" size="sm" color="red">
                  {form.values.identifier_keywords.length}
                </Badge>
              </Tabs.Tab>
              <Tabs.Tab value="global" color="blue">
                Global Keywords
                <Badge ml="xs" size="sm" color="blue">
                  {form.values.global_keywords.length}
                </Badge>
              </Tabs.Tab>
              <Tabs.Tab value="high_confidence" color="violet">
                High Confidence
                <Badge ml="xs" size="sm" color="violet">
                  {form.values.high_confidence_keywords.length}
                </Badge>
              </Tabs.Tab>
              <Tabs.Tab value="general" color="green">
                General
                <Badge ml="xs" size="sm" color="green">
                  {form.values.general_keywords.length}
                </Badge>
              </Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel value="identifier" pt="md">
              <Text size="sm" mb="xs" color="dimmed">
                Keywords that identify your content (organization names, project codes, etc.)
              </Text>
              <KeywordPanel 
                color="red"
                keywords={form.values.identifier_keywords}
                onRemove={(keyword) => removeKeyword('identifier', keyword)}
              />
            </Tabs.Panel>
            
            <Tabs.Panel value="global" pt="md">
              <Text size="sm" mb="xs" color="dimmed">
                High confidence keywords that relate to broader topics
              </Text>
              <KeywordPanel 
                color="blue"
                keywords={form.values.global_keywords}
                onRemove={(keyword) => removeKeyword('global', keyword)}
              />
            </Tabs.Panel>
            
            <Tabs.Panel value="high_confidence" pt="md">
              <Text size="sm" mb="xs" color="dimmed">
                Highly confidential keywords specific to this area
              </Text>
              <KeywordPanel 
                color="violet"
                keywords={form.values.high_confidence_keywords}
                onRemove={(keyword) => removeKeyword('high_confidence', keyword)}
              />
            </Tabs.Panel>
            
            <Tabs.Panel value="general" pt="md">
              <Text size="sm" mb="xs" color="dimmed">
                General keywords that add context but are less sensitive
              </Text>
              <KeywordPanel 
                color="green"
                keywords={form.values.general_keywords}
                onRemove={(keyword) => removeKeyword('general', keyword)}
              />
            </Tabs.Panel>
          </Tabs>
          
          <Group position="apart" mt="lg">
            <Group>
              <TextInput
                placeholder="Add new keyword"
                value={newKeyword}
                onChange={(e) => setNewKeyword(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addKeyword();
                  }
                }}
                rightSection={
                  <ActionIcon onClick={addKeyword} color={getTabColor(activeTab)}>
                    <IconPlus size={16} />
                  </ActionIcon>
                }
              />
            </Group>
            
            <Group>
              <Button variant="default" onClick={() => form.reset()}>
                Reset
              </Button>
              <Button type="submit" loading={isLoading}>
                {dictionary ? 'Update Dictionary' : 'Create Dictionary'}
              </Button>
            </Group>
          </Group>
        </form>
      </Paper>
      
      <Card mt="md" p="md" radius="md" withBorder>
        <Title order={4} mb="sm">Dictionary Statistics</Title>
        <Group>
          <StatBadge 
            label="Identifiers" 
            count={form.values.identifier_keywords.length} 
            color="red" 
          />
          <StatBadge 
            label="Global Keywords" 
            count={form.values.global_keywords.length} 
            color="blue" 
          />
          <StatBadge 
            label="High Confidence" 
            count={form.values.high_confidence_keywords.length} 
            color="violet" 
          />
          <StatBadge 
            label="General" 
            count={form.values.general_keywords.length} 
            color="green" 
          />
          <StatBadge 
            label="Total Keywords" 
            count={
              form.values.identifier_keywords.length +
              form.values.global_keywords.length +
              form.values.high_confidence_keywords.length +
              form.values.general_keywords.length
            } 
            color="gray" 
          />
        </Group>
      </Card>
    </Box>
  );
};

// Helper components
const KeywordPanel = ({ keywords, onRemove, color }) => {
  return (
    <Box mt="sm">
      {keywords.length === 0 ? (
        <Text color="dimmed" size="sm" italic>No keywords added yet</Text>
      ) : (
        <Group spacing={8}>
          {keywords.map((keyword) => (
            <Badge 
              key={keyword} 
              color={color}
              size="lg"
              radius="sm"
              rightSection={
                <ActionIcon 
                  size="xs" 
                  color={color} 
                  radius="xl" 
                  variant="transparent"
                  onClick={() => onRemove(keyword)}
                >
                  <IconTrash size={10} />
                </ActionIcon>
              }
            >
              {keyword}
            </Badge>
          ))}
        </Group>
      )}
    </Box>
  );
};

const StatBadge = ({ label, count, color }) => (
  <Badge 
    color={color} 
    size="lg" 
    variant="dot"
    style={{ minWidth: 80 }}
  >
    {label}: {count}
  </Badge>
);

// Helper function to get tab color
function getTabColor(tab) {
  switch (tab) {
    case 'identifier': return 'red';
    case 'global': return 'blue';
    case 'high_confidence': return 'violet';
    case 'general': return 'green';
    default: return 'gray';
  }
}

export default KeywordDictionaryForm;