import { motion } from "framer-motion";

interface ModalProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  onConfirm?: () => void;
  confirmLabel?: string;
  loading?: boolean;
  children?: React.ReactNode;
}

export function Modal({
  open,
  title,
  description,
  onClose,
  onConfirm,
  confirmLabel = "Confirm",
  loading = false,
  children,
}: ModalProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <motion.div
        initial={{ opacity: 0, y: 12, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0 }}
        className="glass-panel w-full max-w-lg space-y-4 p-6"
      >
        <div>
          <h3 className="text-xl font-semibold text-white">{title}</h3>
          {description && <p className="mt-2 text-sm text-muted">{description}</p>}
        </div>
        {children}
        <div className="flex justify-end gap-3">
          <button className="btn-ghost" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          {onConfirm && (
            <button className="btn-primary" onClick={onConfirm} disabled={loading}>
              {loading ? "Preparing..." : confirmLabel}
            </button>
          )}
        </div>
      </motion.div>
    </div>
  );
}
