import { ResearchBenchmarksData } from '../types/research';

export const fallbackBenchmarkData: ResearchBenchmarksData = {
  baseline: {
    experiment_id: '4eb72e4c-2ba5-47c8-ad1b-9d992b709f61',
    dataset_version: '6.0.0',
    modes: {
      SPEC_ONLY: {
        overall: {
          tp: 4,
          fp: 4,
          fn: 4,
          tn: 10,
          precision: 0.5,
          recall: 0.5,
          f1: 0.5,
          fpr: 0.2857,
          fnr: 0.5,
        },
        categories: {
          authentication: { tp: 1, fp: 1, fn: 0, tn: 3, precision: 0.5, recall: 1.0, f1: 0.6667, fpr: 0.25, fnr: 0.0 },
          authorization: { tp: 1, fp: 2, fn: 2, tn: 0, precision: 0.3333, recall: 0.3333, f1: 0.3333, fpr: 1.0, fnr: 0.6667 },
          input_validation: { tp: 1, fp: 1, fn: 1, tn: 1, precision: 0.5, recall: 0.5, f1: 0.5, fpr: 0.5, fnr: 0.5 },
          sensitive_data: { tp: 1, fp: 0, fn: 0, tn: 3, precision: 1.0, recall: 1.0, f1: 1.0, fpr: 0.0, fnr: 0.0 },
          secrets: { tp: 0, fp: 0, fn: 1, tn: 3, precision: null, recall: 0.0, f1: null, fpr: 0.0, fnr: 1.0 },
        },
      },
      SOURCE_ONLY: {
        overall: {
          tp: 5,
          fp: 4,
          fn: 3,
          tn: 10,
          precision: 0.5556,
          recall: 0.625,
          f1: 0.5882,
          fpr: 0.2857,
          fnr: 0.375,
        },
        categories: {
          authentication: { tp: 1, fp: 1, fn: 0, tn: 3, precision: 0.5, recall: 1.0, f1: 0.6667, fpr: 0.25, fnr: 0.0 },
          authorization: { tp: 2, fp: 2, fn: 1, tn: 0, precision: 0.5, recall: 0.6667, f1: 0.5714, fpr: 1.0, fnr: 0.3333 },
          input_validation: { tp: 0, fp: 1, fn: 2, tn: 1, precision: 0.0, recall: 0.0, f1: null, fpr: 0.5, fnr: 1.0 },
          sensitive_data: { tp: 1, fp: 0, fn: 0, tn: 3, precision: 1.0, recall: 1.0, f1: 1.0, fpr: 0.0, fnr: 0.0 },
          secrets: { tp: 1, fp: 0, fn: 0, tn: 3, precision: 1.0, recall: 1.0, f1: 1.0, fpr: 0.0, fnr: 0.0 },
        },
      },
      CORRELATED: {
        overall: {
          tp: 5,
          fp: 1,
          fn: 3,
          tn: 13,
          precision: 0.8333,
          recall: 0.625,
          f1: 0.7143,
          fpr: 0.0714,
          fnr: 0.375,
        },
        categories: {
          authentication: { tp: 1, fp: 0, fn: 0, tn: 4, precision: 1.0, recall: 1.0, f1: 1.0, fpr: 0.0, fnr: 0.0 },
          authorization: { tp: 2, fp: 0, fn: 1, tn: 2, precision: 1.0, recall: 0.6667, f1: 0.8, fpr: 0.0, fnr: 0.3333 },
          input_validation: { tp: 1, fp: 1, fn: 1, tn: 1, precision: 0.5, recall: 0.5, f1: 0.5, fpr: 0.5, fnr: 0.5 },
          sensitive_data: { tp: 1, fp: 0, fn: 0, tn: 3, precision: 1.0, recall: 1.0, f1: 1.0, fpr: 0.0, fnr: 0.0 },
          secrets: { tp: 0, fp: 0, fn: 1, tn: 3, precision: null, recall: 0.0, f1: null, fpr: 0.0, fnr: 1.0 },
        },
      },
    },
  },
  external: {
    experiment_id: '8c9d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f',
    dataset_version: '7.3.0',
    modes: {
      SPEC_ONLY: {
        overall: {
          tp: 4,
          fp: 2,
          fn: 3,
          tn: 3,
          precision: 0.6667,
          recall: 0.5714,
          f1: 0.6154,
          fpr: 0.4,
          fnr: 0.4286,
        },
        categories: {
          authentication: { tp: 3, fp: 2, fn: 1, tn: 3, precision: 0.6, recall: 0.75, f1: 0.6667, fpr: 0.4, fnr: 0.25 },
          authorization: { tp: 0, fp: 0, fn: 2, tn: 0, precision: null, recall: 0.0, f1: null, fpr: null, fnr: 1.0 },
          sensitive_data: { tp: 1, fp: 0, fn: 0, tn: 0, precision: 1.0, recall: 1.0, f1: 1.0, fpr: null, fnr: 0.0 },
        },
      },
      SOURCE_ONLY: {
        overall: {
          tp: 0,
          fp: 0,
          fn: 7,
          tn: 5,
          precision: null,
          recall: 0.0,
          f1: null,
          fpr: 0.0,
          fnr: 1.0,
        },
        categories: {
          authentication: { tp: 0, fp: 0, fn: 4, tn: 5, precision: null, recall: 0.0, f1: null, fpr: 0.0, fnr: 1.0 },
          authorization: { tp: 0, fp: 0, fn: 2, tn: 0, precision: null, recall: 0.0, f1: null, fpr: null, fnr: 1.0 },
          sensitive_data: { tp: 0, fp: 0, fn: 1, tn: 0, precision: null, recall: 0.0, f1: null, fpr: null, fnr: 1.0 },
        },
      },
      CORRELATED: {
        overall: {
          tp: 0,
          fp: 0,
          fn: 7,
          tn: 5,
          precision: null,
          recall: 0.0,
          f1: null,
          fpr: 0.0,
          fnr: 1.0,
        },
        categories: {
          authentication: { tp: 0, fp: 0, fn: 4, tn: 5, precision: null, recall: 0.0, f1: null, fpr: 0.0, fnr: 1.0 },
          authorization: { tp: 0, fp: 0, fn: 2, tn: 0, precision: null, recall: 0.0, f1: null, fpr: null, fnr: 1.0 },
          sensitive_data: { tp: 0, fp: 0, fn: 1, tn: 0, precision: null, recall: 0.0, f1: null, fpr: null, fnr: 1.0 },
        },
      },
    },
  },
  phase7: {
    confidence_intervals: [
      { metric: 'precision', mode: 'CORRELATED', estimate: 0.8333, lower: 0.3588, upper: 0.9958, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'recall', mode: 'CORRELATED', estimate: 0.625, lower: 0.2449, upper: 0.9148, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'f1', mode: 'CORRELATED', estimate: 0.7143, lower: 0.3556, upper: 0.8929, confidence_level: 0.95, method: 'Bootstrap BCa' },
      { metric: 'precision', mode: 'SPEC_ONLY', estimate: 0.5, lower: 0.157, upper: 0.843, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'recall', mode: 'SPEC_ONLY', estimate: 0.5, lower: 0.157, upper: 0.843, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'f1', mode: 'SPEC_ONLY', estimate: 0.5, lower: 0.1875, upper: 0.75, confidence_level: 0.95, method: 'Bootstrap BCa' },
      { metric: 'precision', mode: 'SOURCE_ONLY', estimate: 0.5556, lower: 0.212, upper: 0.863, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'recall', mode: 'SOURCE_ONLY', estimate: 0.625, lower: 0.2449, upper: 0.9148, confidence_level: 0.95, method: 'Wilson Score' },
      { metric: 'f1', mode: 'SOURCE_ONLY', estimate: 0.5882, lower: 0.2857, upper: 0.8, confidence_level: 0.95, method: 'Bootstrap BCa' },
    ],
    mode_comparisons: [
      { comparison: 'CORRELATED vs SPEC_ONLY', metric: 'precision', difference: 0.3333, ci_lower: 0.05, ci_upper: 0.65, significant: true },
      { comparison: 'CORRELATED vs SPEC_ONLY', metric: 'fpr', difference: -0.2143, ci_lower: -0.45, ci_upper: -0.02, significant: true },
      { comparison: 'CORRELATED vs SOURCE_ONLY', metric: 'precision', difference: 0.2778, ci_lower: 0.01, ci_upper: 0.58, significant: true },
    ],
  },
};
