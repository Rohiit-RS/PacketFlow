"use client";

import React, { createContext, useContext, useState, useEffect, useTransition } from "react";
import { AnalysisEngineResult, ParsedPacket } from "../engine/types";
import { SAMPLE_SCENARIOS, SampleCaptureScenario } from "../samples/sampleData";
import { DiagnosticEngine } from "../engine/diagnosticEngine";
import { toast } from "sonner";

interface CaptureContextType {
  analysisResult: AnalysisEngineResult;
  currentCaptureName: string;
  isProcessing: boolean;
  loadScenario: (scenario: SampleCaptureScenario) => void;
  uploadFile: (file: File) => Promise<void>;
  pasteJson: (jsonString: string) => void;
  getFindingById: (id: string) => any | undefined;
  getPacketByFrame: (frameNum: number) => ParsedPacket | undefined;
}

const defaultScenario = SAMPLE_SCENARIOS[0];
const initialResult = DiagnosticEngine.analyzePackets(defaultScenario.packets);

const CaptureContext = createContext<CaptureContextType | undefined>(undefined);

const STORAGE_KEY = "packetflow_current_state";

export function CaptureProvider({ children }: { children: React.ReactNode }) {
  const [currentCaptureName, setCurrentCaptureName] = useState<string>(defaultScenario.name);
  const [analysisResult, setAnalysisResult] = useState<AnalysisEngineResult>(initialResult);
  const [isProcessing, startTransition] = useTransition();

  // Load from sessionStorage on mount if available
  useEffect(() => {
    try {
      const saved = sessionStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.packets && Array.isArray(parsed.packets)) {
          const res = DiagnosticEngine.analyzePackets(parsed.packets);
          setAnalysisResult(res);
          if (parsed.name) setCurrentCaptureName(parsed.name);
        }
      }
    } catch {}
  }, []);

  const saveToSession = (name: string, packets: ParsedPacket[]) => {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ name, packets }));
    } catch {}
  };

  const loadScenario = (scenario: SampleCaptureScenario) => {
    startTransition(() => {
      try {
        const result = DiagnosticEngine.analyzePackets(scenario.packets);
        setAnalysisResult(result);
        setCurrentCaptureName(scenario.name);
        saveToSession(scenario.name, scenario.packets);
        toast.success(`Loaded "${scenario.name}" (${scenario.packetCount} packets)`);
      } catch (err) {
        toast.error(`Error analyzing scenario: ${err instanceof Error ? err.message : String(err)}`);
      }
    });
  };

  const uploadFile = async (file: File) => {
    try {
      const buffer = await file.arrayBuffer();
      const fileName = file.name;
      let result: AnalysisEngineResult;

      if (fileName.toLowerCase().endsWith(".json")) {
        const text = new TextDecoder().decode(buffer);
        result = DiagnosticEngine.analyzeJsonTelemetry(text);
      } else {
        result = DiagnosticEngine.analyzePcapBuffer(buffer);
      }

      setAnalysisResult(result);
      setCurrentCaptureName(fileName);
      saveToSession(fileName, result.packets);
      toast.success(`Successfully analyzed ${result.stats.total_packets} packets from ${fileName}`);
    } catch (err) {
      toast.error(`Capture parse failed: ${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  };

  const pasteJson = (jsonString: string) => {
    try {
      const result = DiagnosticEngine.analyzeJsonTelemetry(jsonString);
      setAnalysisResult(result);
      setCurrentCaptureName("Pasted Telemetry Logs");
      saveToSession("Pasted Telemetry Logs", result.packets);
      toast.success("Packet telemetry analyzed successfully!");
    } catch (err) {
      toast.error(`Parsing failed: ${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  };

  const getFindingById = (id: string) => {
    return analysisResult.report.findings.find(f => f.id.toLowerCase() === id.toLowerCase());
  };

  const getPacketByFrame = (frameNum: number) => {
    return analysisResult.packets.find(p => p.frame_number === frameNum);
  };

  return (
    <CaptureContext.Provider
      value={{
        analysisResult,
        currentCaptureName,
        isProcessing,
        loadScenario,
        uploadFile,
        pasteJson,
        getFindingById,
        getPacketByFrame,
      }}
    >
      {children}
    </CaptureContext.Provider>
  );
}

export function useCapture() {
  const ctx = useContext(CaptureContext);
  if (!ctx) {
    throw new Error("useCapture must be used within a CaptureProvider");
  }
  return ctx;
}
