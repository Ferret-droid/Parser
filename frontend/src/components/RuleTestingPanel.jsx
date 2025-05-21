import React, { useState } from 'react';
import {
  Box,
  Title,
  Paper,
  Textarea,
  Button,
  Group,
  Select,
  MultiSelect,
  Stack,
  Text,
  Alert,
  Badge,
  Progress,
  Divider,
  Card,
  Accordion,
  List,
  ThemeIcon,
  ScrollArea,
  Tooltip
} from '@mantine/core';
import {
  IconAlertCircle,
  IconCheck,
  IconX,
  IconShieldLock,
  IconKey,
  IconUserCheck,
  IconUserX,
  IconFileAnalytics,
  IconAlertTriangle,
  IconCircle
} from '@tabler/icons-react';

const RuleTestingPanel = ({
  onTestRule,
  isLoading = false,
  users = [],
  roles = [],
  scenarios = []
}) => {
  const [testText, setTestText] = useState('');
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedRoles, setSelectedRoles] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [testingMethod, setTestingMethod] = useState('manual'); // 'manual' or 'scenario'

  // Run the test based on the selected method
  const runTest = async () => {
    if (testingMethod === 'scenario') {
      if (!selectedScenario) return;
      
      const result = await onTestRule({
        type: 'scenario',
        scenario: selectedScenario
      });
      
      setTestResult(result);
    } else {
      if (!testText || !selectedUser) return;
      
      const result = await onTestRule({
        type: 'manual',
        text: testText,
        user_id: selectedUser,
        user_roles: selectedRoles,
        context: 'manual_test'
      });
      
      setTestResult(result);
    }
  };

  // Clear all test data
  const clearTest = () => {
    setTestText('');
    setSelectedUser('');
    setSelectedRoles([]);
    setSelectedScenario('');
    setTestResult(null);
  };

  // Load a predefined scenario
  const loadScenario = (scenarioId) => {
    setSelectedScenario(scenarioId);
    setTestingMethod('scenario');
  };

  return (
    <Box>
      <Paper p="md" radius="md" withBorder mb="md">
        <Title order={3} mb="md">Rule Testing Panel</Title>
        
        <Group grow mb="md">
          <Button
            variant={testingMethod === 'manual' ? 'filled' : 'outline'}
            onClick={() => setTestingMethod('manual')}
          >
            Manual Testing
          </Button>
          <Button
            variant={testingMethod === 'scenario' ? 'filled' : 'outline'}
            onClick={() => setTestingMethod('scenario')}
          >
            Scenario Testing
          </Button>
        </Group>
        
        {testingMethod === 'manual' ? (
          <Box>
            <Textarea
              label="Test Content"
              placeholder="Enter text to test against the keyword rules"
              required
              minRows={5}
              value={testText}
              onChange={(e) => setTestText(e.target.value)}
              mb="md"
            />
            
            <Group grow mb="md">
              <Select
                label="User"
                placeholder="Select user to test as"
                required
                data={users.map(user => ({
                  value: user.id,
                  label: `${user.full_name} (${user.username})`
                }))}
                value={selectedUser}
                onChange={setSelectedUser}
              />
              
              <MultiSelect
                label="Roles"
                placeholder="Select user roles"
                data={roles.map(role => ({
                  value: role.id,
                  label: role.name
                }))}
                value={selectedRoles}
                onChange={setSelectedRoles}
              />
            </Group>
          </Box>
        ) : (
          <Box>
            <Select
              label="Test Scenario"
              placeholder="Select a predefined scenario"
              required
              data={scenarios.map(scenario => ({
                value: scenario.id,
                label: scenario.name
              }))}
              value={selectedScenario}
              onChange={setSelectedScenario}
              mb="md"
            />
            
            <Alert icon={<IconAlertCircle size={16} />} color="blue" mb="md">
              Scenario testing uses predefined content and user combinations to test rule effectiveness.
            </Alert>
          </Box>
        )}
        
        <Group position="apart" mt="xl">
          <Button variant="default" onClick={clearTest}>
            Clear
          </Button>
          <Button 
            onClick={runTest} 
            loading={isLoading}
            disabled={(testingMethod === 'manual' && (!testText || !selectedUser)) || 
                      (testingMethod === 'scenario' && !selectedScenario)}
          >
            Run Test
          </Button>
        </Group>
      </Paper>
      
      {testResult && (
        <TestResultDisplay result={testResult} />
      )}
    </Box>
  );
};

const TestResultDisplay = ({ result }) => {
  // Get color for sensitivity level
  const getSensitivityColor = (level) => {
    switch (level) {
      case 'sensitive': return 'red';
      case 'confidential': return 'orange';
      case 'internal': return 'yellow';
      case 'general': return 'green';
      default: return 'gray';
    }
  };
  
  return (
    <Paper p="md" radius="md" withBorder>
      <Title order={3} mb="md">Test Results</Title>
      
      <Group position="apart" mb="lg">
        <Group>
          <Badge 
            size="lg" 
            color={getSensitivityColor(result.sensitivity_level)}
          >
            {result.sensitivity_level?.toUpperCase()}
          </Badge>
          
          <Badge 
            size="lg" 
            color={result.access_granted ? 'green' : 'red'}
          >
            {result.action_required}
          </Badge>
        </Group>
        
        <Text color="dimmed" size="sm">
          Analysis ID: {result.analysis_id}
        </Text>
      </Group>
      
      <Card withBorder mb="md">
        <Group position="apart" mb="sm">
          <Text weight={500}>Keyword Match Analysis</Text>
          <Badge>{Object.values(result.category_analysis).reduce((sum, cat) => 
            sum + cat.total_matches, 0)} total matches</Badge>
        </Group>
        
        <Stack spacing="xs">
          <CategoryMatchBar 
            category="Identifiers" 
            data={result.category_analysis.identifier}
            color="red"
          />
          <CategoryMatchBar 
            category="High Confidence" 
            data={result.category_analysis.high_confidence}
            color="violet"
          />
          <CategoryMatchBar 
            category="General" 
            data={result.category_analysis.general}
            color="green"
          />
        </Stack>
      </Card>
      
      <Accordion mb="md">
        <Accordion.Item value="matches">
          <Accordion.Control>
            <Group>
              <IconKey size={18} />
              <Text>Matched Keywords</Text>
            </Group>
          </Accordion.Control>
          <Accordion.Panel>
            <ScrollArea h={200}>
              {Object.entries(result.category_analysis).map(([category, data]) => {
                if (data.matches.length === 0) return null;
                
                return (
                  <Box key={category} mb="md">
                    <Text weight={500} mb="xs" tt="capitalize">
                      {category} Keywords:
                    </Text>
                    <Group spacing={8}>
                      {data.matches.map(keyword => (
                        <Badge 
                          key={keyword} 
                          color={getCategoryColor(category)}
                          size="lg"
                          radius="sm"
                        >
                          {keyword}
                        </Badge>
                      ))}
                    </Group>
                  </Box>
                );
              })}
            </ScrollArea>
          </Accordion.Panel>
        </Accordion.Item>
        
        <Accordion.Item value="permissions">
          <Accordion.Control>
            <Group>
              <IconUserCheck size={18} />
              <Text>User Permissions</Text>
            </Group>
          </Accordion.Control>
          <Accordion.Panel>
            <Group>
              <Text>User: {result.user_id}</Text>
              <Text>Roles: {result.user_roles.join(', ')}</Text>
            </Group>
            
            <Divider my="sm" />
            
            {result.access_granted ? (
              <Alert color="green" icon={<IconCheck size={16} />}>
                User has permission to access this content (via roles: {result.authorized_roles.join(', ')})
              </Alert>
            ) : (
              <Alert color="red" icon={<IconX size={16} />}>
                User does not have sufficient permissions to access this content
              </Alert>
            )}
          </Accordion.Panel>
        </Accordion.Item>
        
        <Accordion.Item value="recommendations">
          <Accordion.Control>
            <Group>
              <IconFileAnalytics size={18} />
              <Text>Recommendations</Text>
            </Group>
          </Accordion.Control>
          <Accordion.Panel>
            <List
              spacing="xs"
              size="sm"
              center
              icon={
                <ThemeIcon color="blue" size={20} radius="xl">
                  <IconCircle size={10} />
                </ThemeIcon>
              }
            >
              {result.recommendations.map((rec, index) => (
                <List.Item key={index}>{rec}</List.Item>
              ))}
            </List>
          </Accordion.Panel>
        </Accordion.Item>
      </Accordion>
      
      {result.rule_triggered && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />}>
          <Text weight={600} mb="xs">Combination Rule Triggered!</Text>
          <Text size="sm">
            This content triggered a combination rule, indicating a high probability of sensitive content.
          </Text>
        </Alert>
      )}
    </Paper>
  );
};

const CategoryMatchBar = ({ category, data, color }) => {
  // Calculate what percentage of threshold is met
  const percentage = data.threshold > 0 
    ? Math.min((data.total_matches / data.threshold) * 100, 100) 
    : 0;
  
  return (
    <Box>
      <Group position="apart" mb={5}>
        <Text size="sm">{category}</Text>
        <Group spacing={5}>
          <Text size="sm" color={data.threshold_met ? color : 'dimmed'}>
            {data.total_matches} / {data.threshold} required
          </Text>
          {data.threshold_met && (
            <Tooltip label="Threshold met">
              <ThemeIcon color={color} size={16} radius="xl">
                <IconCheck size={10} />
              </ThemeIcon>
            </Tooltip>
          )}
        </Group>
      </Group>
      <Progress 
        value={percentage} 
        color={data.threshold_met ? color : 'gray'} 
        size="sm" 
      />
    </Box>
  );
};

// Helper to get color for keyword category
const getCategoryColor = (category) => {
  switch (category) {
    case 'identifier': return 'red';
    case 'high_confidence': return 'violet';
    case 'general': return 'green';
    default: return 'blue';
  }
};

export default RuleTestingPanel;